"""Router (MikroTik) inventory. Phase 2 stores configuration only; no device connections are made."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, security
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import AccessMode, Router
from ..rbac import Perm
from ..schemas import RouterCreate, RouterOut, RouterUpdate

router = APIRouter(prefix="/routers", tags=["routers"])


def _out(r: Router) -> RouterOut:
    o = RouterOut.model_validate(r)
    o.has_api_password = bool(r.api_password_enc)
    return o


def _encrypt(pw: str) -> str:
    try:
        return security.encrypt_secret(pw)
    except security.CredentialKeyMissing:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "SHIELD_CREDENTIAL_KEY is not configured; cannot store router credentials") from None


@router.get("", response_model=list[RouterOut])
def list_routers(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return [_out(r) for r in db.execute(select(Router).order_by(Router.name)).scalars()]


@router.get("/{router_id}", response_model=RouterOut)
def get_router(router_id: int, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    r = db.get(Router, router_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Router not found")
    return _out(r)


@router.post("", response_model=RouterOut, status_code=201)
def create_router(body: RouterCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                  db: Session = Depends(get_db)):
    data = body.model_dump(exclude={"api_password"})
    r = Router(**data, dry_run=True)
    if body.api_password:
        r.api_password_enc = _encrypt(body.api_password)
    db.add(r)
    record_change(db, p.actor, "router.create", "router", r)
    return _out(r)


@router.patch("/{router_id}", response_model=RouterOut)
def update_router(router_id: int, body: RouterUpdate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                  db: Session = Depends(get_db)):
    r = db.get(Router, router_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Router not found")
    before = audit.snapshot(r)
    data = body.model_dump(exclude_unset=True)
    pw = data.pop("api_password", None)
    for k, v in data.items():
        if v is not None:
            setattr(r, k, v)
    if pw:
        r.api_password_enc = _encrypt(pw)
    if r.access_mode == AccessMode.READ_WRITE and not (r.use_tls and r.verify_tls):
        raise HTTPException(422, "read_write access requires verified TLS")
    if data.get("dry_run") is False and r.access_mode != AccessMode.READ_WRITE:
        raise HTTPException(422, "dry_run can only be disabled on read_write routers")
    record_change(db, p.actor, "router.update", "router", r, before=before)
    return _out(r)


@router.delete("/{router_id}", status_code=204)
def delete_router(router_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    r = db.get(Router, router_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Router not found")
    before = audit.snapshot(r)
    db.delete(r)
    record_change(db, p.actor, "router.delete", "router", None, entity_id=router_id, before=before)
