from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit, security
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, client_ip, get_principal, require
from ..models import AuthSession, LoginAttempt, User
from ..ratelimit import limiter
from ..rbac import ROLE_PERMISSIONS, Perm
from ..schemas import (
    LoginIn, MeOut, MfaCodeIn, MfaSetupOut, PasswordChangeIn, RefreshIn, SessionOut, TokenOut, UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC = "Invalid username, password or code"


def _issue(db: Session, user: User, mfa: bool, ip: str | None, ua: str | None) -> TokenOut:
    s = get_settings()
    refresh, refresh_hash = security.new_refresh_token()
    sess = AuthSession(
        user_id=user.id, refresh_token_hash=refresh_hash, mfa_verified=mfa,
        expires_at=datetime.now(UTC) + timedelta(seconds=s.refresh_token_ttl_seconds),
        ip=ip, user_agent=(ua or "")[:512] or None,
    )
    db.add(sess)
    db.flush()
    return TokenOut(
        access_token=security.create_access_token(user.id, user.role.value, sess.id, mfa),
        refresh_token=refresh, expires_in=s.access_token_ttl_seconds, mfa_verified=mfa,
    )


def _fail(db: Session, username: str, user: User | None, ip, ua, reason: str, *, detail: str = _GENERIC):
    s = get_settings()
    db.add(LoginAttempt(username=username[:64], user_id=user.id if user else None, ip=ip,
                        user_agent=(ua or "")[:512] or None, success=False, reason=reason))
    if user is not None and reason in ("bad_password", "bad_totp"):
        user.failed_login_count += 1
        if user.failed_login_count >= s.login_max_failures:
            user.locked_until = datetime.now(UTC) + timedelta(seconds=s.login_lockout_seconds)
            user.failed_login_count = 0
            audit.record(db, audit.Actor(None, "system", ip, ua), "auth.lockout", "user", user.id,
                         after={"username": user.username, "locked_until": user.locked_until})
    db.commit()  # persist the failure even though we raise
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request)
    ua = request.headers.get("user-agent")
    for key in (f"login-ip:{ip}", f"login-user:{body.username.lower()}"):
        ok, retry = limiter.hit(key, s.login_rate_per_minute)
        if not ok:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts",
                                headers={"Retry-After": str(int(retry) + 1)})

    user = db.execute(
        select(User).where(func.lower(User.username) == body.username.lower())
    ).scalar_one_or_none()
    pw_ok = security.verify_password(user.password_hash if user else None, body.password)
    now = datetime.now(UTC)

    if user is None:
        _fail(db, body.username, None, ip, ua, "unknown_user")
    if not user.is_active:
        _fail(db, body.username, user, ip, ua, "disabled")
    if user.locked_until and user.locked_until > now:
        _fail(db, body.username, user, ip, ua, "locked")
    if not pw_ok:
        _fail(db, body.username, user, ip, ua, "bad_password")

    mfa = False
    if user.mfa_enabled:
        if not body.totp_code:
            # Password was correct; tell the client to prompt for the code. Not counted as a failure.
            db.add(LoginAttempt(username=user.username, user_id=user.id, ip=ip, success=False, reason="mfa_required"))
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa_required")
        secret = security.decrypt_secret(user.mfa_secret_enc)  # type: ignore[arg-type]
        if not security.verify_totp(secret, body.totp_code):
            _fail(db, body.username, user, ip, ua, "bad_totp")
        mfa = True

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
    db.add(LoginAttempt(username=user.username, user_id=user.id, ip=ip,
                        user_agent=(ua or "")[:512] or None, success=True))
    tokens = _issue(db, user, mfa, ip, ua)
    audit.record(db, audit.Actor(user.id, user.username, ip, ua), "auth.login", "user", user.id,
                 after={"mfa": mfa})
    return tokens


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    h = security.hash_refresh_token(body.refresh_token)
    sess = db.execute(select(AuthSession).where(AuthSession.refresh_token_hash == h).with_for_update()).scalar_one_or_none()
    now = datetime.now(UTC)
    if sess is None or sess.revoked_at is not None or sess.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    new_token, new_hash = security.new_refresh_token()
    sess.refresh_token_hash = new_hash  # rotation: the old refresh token is now useless
    sess.last_used_at = now
    sess.ip = client_ip(request)
    return TokenOut(
        access_token=security.create_access_token(user.id, user.role.value, sess.id, sess.mfa_verified),
        refresh_token=new_token, expires_in=s.access_token_ttl_seconds, mfa_verified=sess.mfa_verified,
    )


@router.post("/logout", status_code=204)
def logout(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    sess = db.get(AuthSession, p.session_id)
    if sess and sess.revoked_at is None:
        sess.revoked_at = datetime.now(UTC)
        sess.revoke_reason = "logout"
    audit.record(db, p.actor, "auth.logout", "user", p.user.id)


@router.get("/me", response_model=MeOut)
def me(p: Principal = Depends(get_principal)):
    out = MeOut.model_validate(
        {**UserOut.model_validate(p.user).model_dump(),
         "permissions": sorted(x.value for x in ROLE_PERMISSIONS[p.user.role]),
         "session_mfa_verified": p.mfa}
    )
    return out


@router.post("/password", status_code=204)
def change_password(body: PasswordChangeIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    if not security.verify_password(p.user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    problems = security.password_problems(body.new_password, p.user.username)
    if problems:
        raise HTTPException(422, {"password": problems})
    p.user.password_hash = security.hash_password(body.new_password)
    p.user.password_changed_at = datetime.now(UTC)
    db.execute(update(AuthSession).where(AuthSession.user_id == p.user.id, AuthSession.id != p.session_id,
                                         AuthSession.revoked_at.is_(None))
               .values(revoked_at=func.now(), revoke_reason="password_change"))
    audit.record(db, p.actor, "auth.password_change", "user", p.user.id)


# ---------------------------------------------------------------- MFA
def _require_credential_key():
    if not get_settings().credential_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "SHIELD_CREDENTIAL_KEY is not configured on the server; MFA is unavailable")


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    _require_credential_key()
    if p.user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled; disable it first")
    secret = security.new_totp_secret()
    p.user.mfa_secret_enc = security.encrypt_secret(secret)
    audit.record(db, p.actor, "auth.mfa_setup_started", "user", p.user.id)
    return MfaSetupOut(secret=secret, otpauth_uri=security.totp_uri(secret, p.user.username))


@router.post("/mfa/enable", response_model=TokenOut)
def mfa_enable(body: MfaCodeIn, request: Request, p: Principal = Depends(require(Perm.VIEW)),
               db: Session = Depends(get_db)):
    _require_credential_key()
    if p.user.mfa_enabled or not p.user.mfa_secret_enc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Run /auth/mfa/setup first")
    if not security.verify_totp(security.decrypt_secret(p.user.mfa_secret_enc), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code")
    p.user.mfa_enabled = True
    # Revoke the current (non-MFA) session and issue an MFA-verified one.
    sess = db.get(AuthSession, p.session_id)
    sess.revoked_at = datetime.now(UTC)
    sess.revoke_reason = "mfa_enabled"
    audit.record(db, p.actor, "auth.mfa_enabled", "user", p.user.id)
    return _issue(db, p.user, True, p.ip, p.user_agent)


@router.post("/mfa/disable", status_code=204)
def mfa_disable(body: MfaCodeIn, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    _require_credential_key()
    if not p.user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is not enabled")
    if not security.verify_totp(security.decrypt_secret(p.user.mfa_secret_enc), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code")
    p.user.mfa_enabled = False
    p.user.mfa_secret_enc = None
    audit.record(db, p.actor, "auth.mfa_disabled", "user", p.user.id)


# ---------------------------------------------------------------- sessions
@router.get("/sessions", response_model=list[SessionOut])
def my_sessions(p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    rows = db.execute(
        select(AuthSession).where(AuthSession.user_id == p.user.id, AuthSession.revoked_at.is_(None),
                                  AuthSession.expires_at > func.now()).order_by(AuthSession.created_at.desc())
    ).scalars().all()
    out = []
    for r in rows:
        o = SessionOut.model_validate(r)
        o.current = r.id == p.session_id
        out.append(o)
    return out


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: uuid.UUID, p: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    sess = db.get(AuthSession, session_id)
    if sess is None or sess.user_id != p.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if sess.revoked_at is None:
        sess.revoked_at = datetime.now(UTC)
        sess.revoke_reason = "user_revoked"
        audit.record(db, p.actor, "auth.session_revoked", "auth_session", sess.id)
