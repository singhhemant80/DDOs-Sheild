"""Password hashing, tokens, TOTP and secret encryption."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

# OWASP 2024 Argon2id baseline: m=19 MiB, t=2, p=1. We go a bit higher.
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# Pre-computed hash used to equalise timing when the username does not exist.
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _ph.check_needs_rehash(password_hash)


def password_problems(password: str, username: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    classes = sum(
        [any(c.islower() for c in password), any(c.isupper() for c in password),
         any(c.isdigit() for c in password), any(not c.isalnum() for c in password)]
    )
    if classes < 3:
        problems.append("must use at least three of: lowercase, uppercase, digits, symbols")
    return problems


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def create_access_token(user_id: uuid.UUID, role: str, session_id: uuid.UUID, mfa: bool) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "role": role,
        "mfa": mfa,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=s.access_token_ttl_seconds),
        "iss": s.jwt_issuer,
        "typ": "access",
    }
    return jwt.encode(payload, s.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    s = get_settings()
    payload = jwt.decode(
        token, s.secret_key, algorithms=["HS256"], issuer=s.jwt_issuer,
        options={"require": ["exp", "sub", "sid", "iss", "typ"]},
    )
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def new_refresh_token() -> tuple[str, str]:
    """Returns (token for client, sha256 hex stored in DB)."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Crapplet DDoS Shield")


def verify_totp(secret: str, code: str) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ---------------------------------------------------------------------------
# Secret encryption at rest (router passwords, MFA secrets, notification tokens)
# ---------------------------------------------------------------------------
class CredentialKeyMissing(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = get_settings().credential_key
    if not key:
        raise CredentialKeyMissing("SHIELD_CREDENTIAL_KEY is not configured")
    return Fernet(key.encode())


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise ValueError("cannot decrypt secret (wrong SHIELD_CREDENTIAL_KEY?)") from e
