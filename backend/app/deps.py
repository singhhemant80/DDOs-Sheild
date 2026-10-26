"""Request dependencies: authentication, authorisation, client identity, rate limits."""
from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .audit import Actor
from .config import get_settings
from .db import get_db
from .models import AuthSession, User
from .ratelimit import limiter
from .rbac import Perm, has_perm
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)
_ADMIN_PERMS = {Perm.MANAGE_USERS, Perm.MANAGE_SETTINGS}
_MITIGATION_PERMS = {Perm.MITIGATION_APPROVE, Perm.AUTOMATION_ENABLE}


def client_ip(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    if peer and peer in get_settings().trusted_proxies:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            candidate = xff.split(",")[-1].strip()  # rightmost = added by our proxy
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    try:
        return str(ipaddress.ip_address(peer)) if peer else None
    except ValueError:
        return None  # e.g. "testclient"


@dataclass
class Principal:
    user: User
    session_id: uuid.UUID
    mfa: bool
    ip: str | None
    user_agent: str | None

    @property
    def actor(self) -> Actor:
        return Actor(self.user.id, self.user.username, self.ip, self.user_agent)


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


def get_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        payload = decode_access_token(creds.credentials)
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _unauthorized("Invalid or expired token") from None

    sess = db.get(AuthSession, session_id)
    now = datetime.now(UTC)
    if sess is None or sess.user_id != user_id or sess.revoked_at is not None or sess.expires_at <= now:
        raise _unauthorized("Session revoked or expired")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized("Account disabled")
    # Role in the token is informational; the DB role is authoritative so demotions apply immediately.
    request.state.user_id = str(user.id)
    return Principal(user, session_id, bool(sess.mfa_verified), client_ip(request),
                     request.headers.get("user-agent"))


def require(perm: Perm, *, mfa: bool = False):
    def dep(request: Request, p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Principal:
        if not has_perm(p.user.role, perm):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires permission: {perm.value}")
        if mfa and not p.mfa:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This action requires an MFA-verified session")
        if perm in _ADMIN_PERMS and not p.mfa:
            from .changes import get_setting
            if get_setting(db, "require_mfa_for_admin", False):
                raise HTTPException(status.HTTP_403_FORBIDDEN,
                                    "Administrator actions require MFA. Enrol via /api/v1/auth/mfa/setup")
        if perm in _MITIGATION_PERMS and not p.mfa:
            from .changes import get_setting
            if get_setting(db, "require_mfa_for_mitigation", False):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Mitigation approval requires an MFA-verified session")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            ok, retry = limiter.hit(f"write:{p.user.id}", get_settings().write_rate_per_minute)
            if not ok:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded",
                                    headers={"Retry-After": str(int(retry) + 1)})
        return p

    return dep
