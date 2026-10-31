"""Scrubbing providers (Phase 9 part 3). The API token is write-only: stored encrypted, never returned."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, security
from .. import netvalidate as nv
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..mitigation import scrubbing as scr
from ..mitigation.speaker import SpeakerError
from ..models import MitigationAction, ScrubbingProvider, Strategy
from ..rbac import Perm

router = APIRouter(prefix="/scrubbing", tags=["scrubbing"])


class ProviderIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9 _.-]{1,64}$")
    enabled: bool = True
    method: str = Field("api", pattern="^(api|manual)$")
    config: dict = Field(default_factory=dict)
    auth_header: str | None = Field(None, pattern=r"^[A-Za-z0-9-]{1,64}$")
    secret: str | None = Field(None, max_length=2000)
    documentation_ref: str | None = Field(None, max_length=1000)
    min_prefix_len: int = Field(24, ge=8, le=48)
    max_prefix_len: int = Field(24, ge=8, le=48)
    max_prefixes: int = Field(4, ge=1, le=1000)
    notes: str | None = Field(None, max_length=2000)


class ProviderUpdate(BaseModel):
    enabled: bool | None = None
    config: dict | None = None
    auth_header: str | None = Field(None, pattern=r"^[A-Za-z0-9-]{0,64}$")
    secret: str | None = Field(None, max_length=2000)   # "" clears it
    documentation_ref: str | None = Field(None, max_length=1000)
    min_prefix_len: int | None = Field(None, ge=8, le=48)
    max_prefix_len: int | None = Field(None, ge=8, le=48)
    max_prefixes: int | None = Field(None, ge=1, le=1000)
    notes: str | None = Field(None, max_length=2000)


def _out(p: ScrubbingProvider) -> dict:
    return {"id": p.id, "name": p.name, "enabled": p.enabled, "method": p.method, "config": p.config or {},
            "auth_header": p.auth_header, "has_secret": bool(p.secret_enc), "documentation_ref": p.documentation_ref,
            "verified_at": p.verified_at, "min_prefix_len": p.min_prefix_len, "max_prefix_len": p.max_prefix_len,
            "max_prefixes": p.max_prefixes, "notes": p.notes}


def _get(db: Session, pid: int) -> ScrubbingProvider:
    p = db.get(ScrubbingProvider, pid)
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scrubbing provider not found")
    return p


def _config(method: str, cfg: dict) -> dict:
    try:
        return scr.validate_config(method, cfg, resolve=False)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


def _encrypt(v: str) -> str:
    try:
        return security.encrypt_secret(v)
    except security.CredentialKeyMissing:
        raise HTTPException(503, "SHIELD_CREDENTIAL_KEY is not configured; cannot store the token") from None


def _live(db: Session, pid: int) -> int:
    return sum(1 for a in db.execute(select(MitigationAction).where(
        MitigationAction.strategy == Strategy.SCRUBBING,
        MitigationAction.state.in_(["proposed", "approved", "executing", "active", "withdrawing", "failed"]))).scalars()
        if ((a.plan or {}).get("route") or {}).get("scrubbing_provider_id") == pid)


@router.get("/providers")
def list_providers(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return [_out(p) for p in db.execute(select(ScrubbingProvider).order_by(ScrubbingProvider.name)).scalars()]


@router.post("/providers", status_code=201)
def create_provider(body: ProviderIn, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    if body.min_prefix_len > body.max_prefix_len:
        raise HTTPException(422, "min_prefix_len must not exceed max_prefix_len")
    prov = ScrubbingProvider(name=body.name, enabled=body.enabled, method=body.method, config=_config(body.method, body.config),
                             auth_header=body.auth_header, documentation_ref=body.documentation_ref,
                             min_prefix_len=body.min_prefix_len, max_prefix_len=body.max_prefix_len,
                             max_prefixes=body.max_prefixes, notes=body.notes)
    if body.secret:
        prov.secret_enc = _encrypt(body.secret)
    db.add(prov)
    record_change(db, p.actor, "scrubbing.create", "scrubbing_provider", prov)
    return _out(prov)


@router.patch("/providers/{pid}")
def update_provider(pid: int, body: ProviderUpdate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    prov = _get(db, pid)
    before = audit.snapshot(prov)
    data = body.model_dump(exclude_unset=True)
    secret = data.pop("secret", None)
    if "config" in data and data["config"] is not None:
        data["config"] = _config(prov.method, data["config"])
    for k, v in data.items():
        if v is not None or k in ("documentation_ref", "notes"):
            setattr(prov, k, v if k != "auth_header" else (v or None))
    if secret == "":
        prov.secret_enc = None
    elif secret:
        prov.secret_enc = _encrypt(secret)
    if prov.min_prefix_len > prov.max_prefix_len:
        raise HTTPException(422, "min_prefix_len must not exceed max_prefix_len")
    if set(data) - {"enabled", "notes"} or secret is not None:
        prov.verified_at = None   # any change to how Shield talks to the provider needs verifying again
    record_change(db, p.actor, "scrubbing.update", "scrubbing_provider", prov, before=before)
    return _out(prov)


@router.delete("/providers/{pid}", status_code=204)
def delete_provider(pid: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    prov = _get(db, pid)
    if _live(db, pid):
        raise HTTPException(409, "This provider has open diversions; withdraw them first")
    before = audit.snapshot(prov)
    db.delete(prov)
    record_change(db, p.actor, "scrubbing.delete", "scrubbing_provider", None, entity_id=pid, before=before)


@router.post("/providers/{pid}/test")
def test_provider(pid: int, prefix: str = Query(..., description="A protected prefix to ask the status of"),
                  p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    """Call the provider's status request (never activate or deactivate) and show the answer."""
    prov = _get(db, pid)
    try:
        net = nv.parse_prefix(prefix)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if prov.method != "api" or not (prov.config or {}).get("status"):
        raise HTTPException(422, "This provider has no status request to test")
    import uuid
    d = scr.Diversion(provider_id=pid, prefix=str(net), target=str(net), action_id=str(uuid.UUID(int=0)))
    try:
        active = scr.HttpScrubbing().is_active(prov, d)
        result = {"ok": True, "active": active}
    except SpeakerError as e:
        result = {"ok": False, "error": str(e)}
    audit.record(db, p.actor, "scrubbing.test", "scrubbing_provider", pid, after=result)
    return result


@router.post("/providers/{pid}/verify")
def verify_provider(pid: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    """Record that someone checked this provider's settings against its documentation."""
    prov = _get(db, pid)
    if not prov.documentation_ref:
        raise HTTPException(422, "Add the provider's documentation (URL or ticket) first")
    if prov.method == "api" and not ((prov.config or {}).get("activate") and (prov.config or {}).get("deactivate")):
        raise HTTPException(422, "Configure the activate and deactivate requests first")
    prov.verified_at = datetime.now(UTC)
    audit.record(db, p.actor, "scrubbing.verify", "scrubbing_provider", pid, after={"documentation": prov.documentation_ref})
    return _out(prov)
