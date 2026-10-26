from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit, security
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import AuthSession, Role, User
from ..rbac import Perm
from ..schemas import UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


def _active_admins(db: Session) -> int:
    return db.execute(select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.is_active)).scalar_one()


def _revoke_all(db: Session, user_id: uuid.UUID, reason: str):
    db.execute(update(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
               .values(revoked_at=func.now(), revoke_reason=reason))


@router.get("", response_model=list[UserOut])
def list_users(_: Principal = Depends(require(Perm.MANAGE_USERS)), db: Session = Depends(get_db)):
    return db.execute(select(User).order_by(User.username)).scalars().all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, p: Principal = Depends(require(Perm.MANAGE_USERS)), db: Session = Depends(get_db)):
    problems = security.password_problems(body.password, body.username)
    if problems:
        raise HTTPException(422, {"password": problems})
    if db.execute(select(User.id).where(func.lower(User.username) == body.username.lower())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    u = User(username=body.username, email=body.email, full_name=body.full_name, role=body.role,
             password_hash=security.hash_password(body.password))
    db.add(u)
    record_change(db, p.actor, "user.create", "user", u)
    return u


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, p: Principal = Depends(require(Perm.MANAGE_USERS)),
                db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    before = audit.snapshot(u)
    data = body.model_dump(exclude_unset=True)

    demoting = "role" in data and data["role"] != Role.ADMIN and u.role == Role.ADMIN
    disabling = data.get("is_active") is False and u.is_active and u.role == Role.ADMIN
    if (demoting or disabling) and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot remove the last active administrator")

    for f in ("email", "full_name", "role", "is_active"):
        if f in data and data[f] is not None:
            setattr(u, f, data[f])
    if data.get("unlock"):
        u.locked_until = None
        u.failed_login_count = 0
    if data.get("reset_mfa"):
        u.mfa_enabled = False
        u.mfa_secret_enc = None
    if data.get("new_password"):
        problems = security.password_problems(data["new_password"], u.username)
        if problems:
            raise HTTPException(422, {"password": problems})
        u.password_hash = security.hash_password(data["new_password"])
        u.password_changed_at = datetime.now(UTC)

    if any(k in data for k in ("role", "is_active", "reset_mfa", "new_password")):
        _revoke_all(db, u.id, "admin_change")
    record_change(db, p.actor, "user.update", "user", u, before=before)
    return u
