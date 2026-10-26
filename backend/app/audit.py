"""Tamper-evident, hash-chained audit log.

hash_n = sha256(prev_hash || canonical_json(entry_n)). Entries are written in the same
transaction as the change they describe. A transaction-scoped advisory lock serialises
writers so the chain never forks.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum

from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from .models import AuditLog

GENESIS = "0" * 64
_LOCK_ID = 0x5348_4945_4C44  # "SHIELD"

# Columns never written to audit snapshots.
REDACT = {"password_hash", "api_password_enc", "mfa_secret_enc", "secret_enc", "refresh_token_hash", "md5_password_enc"}


@dataclass
class Actor:
    user_id: uuid.UUID | None
    username: str
    ip: str | None = None
    user_agent: str | None = None


SYSTEM_ACTOR = Actor(None, "system")


def _jsonable(v):
    if isinstance(v, (datetime,)):
        return v.astimezone(UTC).isoformat()
    if isinstance(v, (uuid.UUID, ipaddress.IPv4Network, ipaddress.IPv6Network,
                      ipaddress.IPv4Address, ipaddress.IPv6Address,
                      ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(v)
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, Enum):
        return v.value
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def snapshot(obj) -> dict:
    """Column snapshot of an ORM object with secrets replaced by a marker."""
    out = {}
    for attr in inspect(obj).mapper.column_attrs:
        k = attr.key
        v = getattr(obj, k)
        if k in REDACT:
            out[k] = "[set]" if v else None
        else:
            out[k] = _jsonable(v)
    return out


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def _entry_dict(row: AuditLog) -> dict:
    return {
        "at": _jsonable(row.at),
        "actor_user_id": _jsonable(row.actor_user_id),
        "actor_username": row.actor_username,
        "actor_ip": _jsonable(row.actor_ip),
        "action": row.action,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "before": row.before,
        "after": row.after,
    }


def compute_hash(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()


def record(
    db: Session,
    actor: Actor,
    action: str,
    entity_type: str | None = None,
    entity_id: object | None = None,
    before: dict | None = None,
    after: dict | None = None,
) -> AuditLog:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_ID})
    prev = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    # Microsecond-truncated UTC so the value round-trips through PostgreSQL unchanged.
    row = AuditLog(
        at=datetime.now(UTC),
        actor_user_id=actor.user_id,
        actor_username=actor.username,
        actor_ip=actor.ip,
        user_agent=(actor.user_agent or "")[:512] or None,
        action=action,
        entity_type=entity_type,
        entity_id=None if entity_id is None else str(entity_id),
        before=_jsonable(before) if before is not None else None,
        after=_jsonable(after) if after is not None else None,
        prev_hash=prev or GENESIS,
    )
    row.hash = compute_hash(row.prev_hash, _entry_dict(row))
    db.add(row)
    db.flush()
    return row


@dataclass
class ChainReport:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str | None = None
    head_hash: str | None = None


def verify_chain(db: Session, batch: int = 5000) -> ChainReport:
    prev = GENESIS
    checked = 0
    last_id = 0
    while True:
        rows = db.execute(
            select(AuditLog).where(AuditLog.id > last_id).order_by(AuditLog.id).limit(batch)
        ).scalars().all()
        if not rows:
            break
        for r in rows:
            if r.prev_hash != prev:
                return ChainReport(False, checked, r.id, "prev_hash does not match previous entry")
            if compute_hash(r.prev_hash, _entry_dict(r)) != r.hash:
                return ChainReport(False, checked, r.id, "entry content does not match its hash")
            prev = r.hash
            checked += 1
            last_id = r.id
    return ChainReport(True, checked, head_hash=prev if checked else None)
