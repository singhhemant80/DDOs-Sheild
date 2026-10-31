"""Alert channels and history (Phase 10). Secrets (SMTP password, bot token, webhook signing key)
are write-only: stored encrypted and never returned."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, security
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import ChannelKind, Notification, NotificationChannel, Severity
from ..notify import senders
from ..notify.events import EVENT_TYPES
from ..rbac import Perm

router = APIRouter(prefix="/notifications", tags=["notifications"])
REPORTS = ("off", "daily", "weekly")


class ChannelIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9 _.-]{1,64}$")
    kind: ChannelKind
    config: dict = Field(default_factory=dict)
    secret: str | None = Field(None, max_length=2000)
    enabled: bool = True
    min_severity: Severity = Severity.MEDIUM
    event_types: list[str] = Field(default_factory=list, max_length=40)
    cooldown_seconds: int = Field(300, ge=0, le=86400)
    escalate_after_seconds: int | None = Field(None, ge=60, le=86400)
    reports: str = Field("off", pattern="^(off|daily|weekly)$")


class ChannelUpdate(BaseModel):
    config: dict | None = None
    secret: str | None = Field(None, max_length=2000)   # "" clears it
    enabled: bool | None = None
    min_severity: Severity | None = None
    event_types: list[str] | None = Field(None, max_length=40)
    cooldown_seconds: int | None = Field(None, ge=0, le=86400)
    escalate_after_seconds: int | None = Field(None, ge=0, le=86400)   # 0 turns escalation off
    reports: str | None = Field(None, pattern="^(off|daily|weekly)$")


def _out(c: NotificationChannel) -> dict:
    cfg = dict(c.config or {})
    return {"id": c.id, "name": c.name, "kind": c.kind.value, "config": cfg, "has_secret": bool(c.secret_enc),
            "enabled": c.enabled, "min_severity": c.min_severity.value, "event_types": list(c.event_types or []),
            "cooldown_seconds": c.cooldown_seconds, "escalate_after_seconds": c.escalate_after_seconds,
            "reports": cfg.get("reports", "off")}


def _config(kind: str, cfg: dict, reports: str) -> dict:
    try:
        out = senders.validate(kind, cfg)
    except (ValueError, TypeError) as e:
        raise HTTPException(422, str(e)) from None
    out["reports"] = reports
    return out


def _types(types: list[str]) -> list[str]:
    bad = [t for t in types if t not in EVENT_TYPES or t == "test"]
    if bad:
        raise HTTPException(422, f"unknown event types: {', '.join(bad)}")
    return sorted(set(types))


def _encrypt(v: str) -> str:
    try:
        return security.encrypt_secret(v)
    except security.CredentialKeyMissing:
        raise HTTPException(503, "SHIELD_CREDENTIAL_KEY is not configured; cannot store the secret") from None


def _get(db: Session, cid: int) -> NotificationChannel:
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    return c


@router.get("/event-types")
def event_types(_: Principal = Depends(require(Perm.VIEW))):
    return [{"type": k, "label": v[0], "severity": v[1]} for k, v in EVENT_TYPES.items() if k != "test"]


@router.get("/channels")
def list_channels(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return [_out(c) for c in db.execute(select(NotificationChannel).order_by(NotificationChannel.name)).scalars()]


@router.post("/channels", status_code=201)
def create_channel(body: ChannelIn, p: Principal = Depends(require(Perm.MANAGE_SETTINGS)), db: Session = Depends(get_db)):
    if body.kind == ChannelKind.TELEGRAM and not body.secret:
        raise HTTPException(422, "Telegram needs the bot token")
    c = NotificationChannel(name=body.name, kind=body.kind, config=_config(body.kind.value, body.config, body.reports),
                            enabled=body.enabled, min_severity=body.min_severity, event_types=_types(body.event_types),
                            cooldown_seconds=body.cooldown_seconds, escalate_after_seconds=body.escalate_after_seconds)
    if body.secret:
        c.secret_enc = _encrypt(body.secret)
    db.add(c)
    record_change(db, p.actor, "notification.channel_create", "notification_channel", c)
    return _out(c)


@router.patch("/channels/{cid}")
def update_channel(cid: int, body: ChannelUpdate, p: Principal = Depends(require(Perm.MANAGE_SETTINGS)),
                   db: Session = Depends(get_db)):
    c = _get(db, cid)
    before = audit.snapshot(c)
    data = body.model_dump(exclude_unset=True)
    reports = data.pop("reports", None) or (c.config or {}).get("reports", "off")
    if "config" in data and data["config"] is not None:
        c.config = _config(c.kind.value, data.pop("config"), reports)
    elif "reports" in body.model_fields_set:
        c.config = {**(c.config or {}), "reports": reports}
    data.pop("config", None)
    secret = data.pop("secret", None)
    if "event_types" in data and data["event_types"] is not None:
        data["event_types"] = _types(data["event_types"])
    if data.get("escalate_after_seconds") == 0:
        data["escalate_after_seconds"] = None
    for k, v in data.items():
        if v is not None or k == "escalate_after_seconds":
            setattr(c, k, v)
    if secret == "":
        c.secret_enc = None
    elif secret:
        c.secret_enc = _encrypt(secret)
    record_change(db, p.actor, "notification.channel_update", "notification_channel", c, before=before)
    return _out(c)


@router.delete("/channels/{cid}", status_code=204)
def delete_channel(cid: int, p: Principal = Depends(require(Perm.MANAGE_SETTINGS)), db: Session = Depends(get_db)):
    c = _get(db, cid)
    before = audit.snapshot(c)
    db.delete(c)
    record_change(db, p.actor, "notification.channel_delete", "notification_channel", None, entity_id=cid, before=before)


@router.post("/channels/{cid}/test")
def test_channel(cid: int, p: Principal = Depends(require(Perm.MANAGE_SETTINGS)), db: Session = Depends(get_db)):
    """Send a test message to this channel now."""
    _get(db, cid)
    from ..notify.service import Notifier
    ok, err = Notifier().send_test(cid)
    audit.record(db, p.actor, "notification.test", "notification_channel", cid, after={"ok": ok})
    return {"ok": ok, "error": err}


@router.get("")
def history(limit: int = Query(100, ge=1, le=1000), channel_id: int | None = None,
            status_: str | None = Query(None, alias="status", pattern="^(pending|sent|suppressed|failed)$"),
            _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    names = dict(db.execute(select(NotificationChannel.id, NotificationChannel.name)).all())
    q = select(Notification).order_by(Notification.id.desc()).limit(limit)
    if channel_id:
        q = q.where(Notification.channel_id == channel_id)
    if status_:
        q = q.where(Notification.status == status_)
    return [{"id": n.id, "at": n.created_at, "channel_id": n.channel_id, "channel": names.get(n.channel_id),
             "event_type": n.event_type, "severity": n.severity.value, "title": (n.payload or {}).get("title"),
             "lines": (n.payload or {}).get("lines") or [], "incident_id": str(n.incident_id) if n.incident_id else None,
             "status": n.status, "attempts": n.attempts, "sent_at": n.sent_at, "error": n.error}
            for n in db.execute(q).scalars()]
