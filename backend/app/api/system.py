"""Health, audit, settings and the emergency stop."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import __version__, audit
from .. import roadmap as rm
from .. import telemetry as tm
from ..changes import get_setting
from ..db import get_db
from ..deps import Principal, require
from ..models import DEFAULT_SETTINGS, AuditLog, SystemSetting
from ..rbac import Perm
from ..schemas import AuditOut, SettingOut, SettingUpdate

router = APIRouter(tags=["system"])


# ---------------------------------------------------------------- health
@router.get("/health")
def health(db: Session = Depends(get_db)):
    """Unauthenticated liveness/readiness probe. Reveals nothing beyond up/down."""
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, {"status": "db_unavailable"}) from None


@router.get("/health/details")
def health_details(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    rev = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return {
        "status": "ok",
        "version": __version__,
        "schema_revision": rev,
        "time": datetime.now(UTC).isoformat(),
        "automation_enabled": get_setting(db, "automation_enabled", False),
        "rtbh_emergency_disable": get_setting(db, "rtbh_emergency_disable", False),
        "components": {
            "api": "up",
            "database": "up",
            "redis": "up" if tm.redis_ok() else "down",
            "clickhouse": "up" if tm.clickhouse_ok() else "down",
            "collector": _collector_state(),
            "detector": _detector_state(),
            "mikrotik_adapter": _mikrotik_state(db),
            "mitigator": _mitigator_state(),
        },
    }


def _mitigator_state() -> str:
    """up: controller heartbeat fresh and it holds the lock; degraded: last reconcile failed."""
    try:
        raw = tm.rds().get("shield:mitigator:status")
    except Exception:
        return "down"
    if not raw:
        return "down"
    import json
    st = json.loads(raw)
    if not st.get("leader"):
        return "degraded"
    return "up" if (st.get("last_reconcile") or {}).get("ok", True) else "degraded"


def _mikrotik_state(db: Session) -> str:
    """up: heartbeat fresh and no router down; degraded: some router down; down: no heartbeat
    while routers with credentials exist; idle: nothing to poll."""
    from ..models import DeviceStatus, Router
    polled = db.execute(select(Router.status).where(Router.enabled, Router.api_password_enc.is_not(None))).scalars().all()
    try:
        raw = tm.rds().get("shield:mikrotik:status")
    except Exception:
        raw = None
    if not polled:
        return "idle"
    if not raw:
        return "down"
    return "degraded" if any(s == DeviceStatus.DOWN for s in polled) else "up"


def _detector_state() -> str:
    try:
        raw = tm.rds().get("shield:detector:status")
    except Exception:
        return "down"
    if not raw:
        return "down"
    import json
    st = json.loads(raw)
    lag = st.get("lag_seconds")
    return "degraded" if st.get("in_data_gap") or (lag is not None and lag > 10) else "up"


def _collector_state() -> str:
    st = tm.collector_status()
    if not st.get("running"):
        return "down"
    exporters = st.get("exporters", [])
    if not exporters or all(e.get("stale") for e in exporters):
        return "degraded"  # running but receiving nothing
    return "up"


# ---------------------------------------------------------------- audit
@router.get("/system/roadmap")
def get_roadmap(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Phases done / next / pending, plus this installation's open go-live steps."""
    return rm.roadmap(db)


@router.get("/audit", response_model=list[AuditOut])
def list_audit(
    entity_type: str | None = Query(None, max_length=64),
    entity_id: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
    before_id: int | None = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    _: Principal = Depends(require(Perm.VIEW_AUDIT)),
    db: Session = Depends(get_db),
):
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if entity_type:
        q = q.where(AuditLog.entity_type == entity_type)
    if entity_id:
        q = q.where(AuditLog.entity_id == entity_id)
    if action:
        q = q.where(AuditLog.action == action)
    if before_id:
        q = q.where(AuditLog.id < before_id)
    return db.execute(q).scalars().all()


@router.get("/audit/verify")
def verify_audit(_: Principal = Depends(require(Perm.VIEW_AUDIT)), db: Session = Depends(get_db)):
    r = audit.verify_chain(db)
    return {"ok": r.ok, "checked": r.checked, "first_bad_id": r.first_bad_id, "reason": r.reason,
            "head_hash": r.head_hash}


# ---------------------------------------------------------------- settings
@router.get("/settings", response_model=list[SettingOut])
def list_settings(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return db.execute(select(SystemSetting).order_by(SystemSetting.key)).scalars().all()


# Safety switches are changed only through the dedicated endpoints below.
_GUARDED = {"automation_enabled", "rtbh_emergency_disable", "bgp_production_enabled"}


def _validate_setting(key: str, value):
    default = DEFAULT_SETTINGS[key][0]
    if isinstance(default, str):
        if not isinstance(value, str) or len(value) > 255:
            raise HTTPException(422, f"{key} must be text")
        if key == "collector_address" and value:
            import ipaddress
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise HTTPException(422, "collector_address must be an IP address") from None
        if key == "bgp_speaker" and value not in ("simulated", "frr"):
            raise HTTPException(422, "bgp_speaker must be 'simulated' or 'frr'")
        if key == "filter_backend" and value not in ("simulated", "routeros"):
            raise HTTPException(422, "filter_backend must be 'simulated' or 'routeros'")
        if key in ("bgp_router_id", "rtbh_discard_nexthop_v4", "rtbh_discard_nexthop_v6") and value:
            import ipaddress
            want = 6 if key.endswith("v6") else 4
            try:
                ok = ipaddress.ip_address(value).version == want
            except ValueError:
                ok = False
            if not ok:
                raise HTTPException(422, f"{key} must be an IPv{want} address")
        if key == "internal_blackhole_community" and value:
            from .. import netvalidate as nv
            try:
                nv.normalise_community(value)
            except ValueError as e:
                raise HTTPException(422, f"internal_blackhole_community: {e}") from None
        return
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise HTTPException(422, f"{key} must be a boolean")
    elif isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 100_000:
            raise HTTPException(422, f"{key} must be an integer 1-100000")


def _set(db: Session, p: Principal, key: str, value, action: str):
    row = db.get(SystemSetting, key)
    before = {"value": row.value} if row else None
    if row is None:
        row = SystemSetting(key=key, value=value, description=DEFAULT_SETTINGS.get(key, (None, None))[1])
        db.add(row)
    row.value = value
    row.updated_by_id = p.user.id
    row.updated_at = datetime.now(UTC)
    db.flush()
    audit.record(db, p.actor, action, "system_setting", key, before=before, after={"value": value})
    return row


@router.put("/settings/{key}", response_model=SettingOut)
def update_setting(key: str, body: SettingUpdate, p: Principal = Depends(require(Perm.MANAGE_SETTINGS)),
                   db: Session = Depends(get_db)):
    if key not in DEFAULT_SETTINGS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown setting")
    if key in _GUARDED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Use /system/emergency-stop, /system/automation or /system/production")
    _validate_setting(key, body.value)
    if key == "bgp_speaker" and body.value != get_setting(db, "bgp_speaker", "simulated"):
        # Switching speakers with routes in flight would strand them on the old one.
        from ..models import MitigationAction, Strategy
        live = db.execute(select(func.count()).select_from(MitigationAction).where(MitigationAction.state.in_(
            ["proposed", "approved", "executing", "active", "withdrawing", "failed"]),
            MitigationAction.strategy != Strategy.LOCAL_FILTER)).scalar_one()
        if live:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"{live} mitigation actions are still open; withdraw or finish them before switching speaker")
        if body.value == "frr" and not p.mfa and get_setting(db, "require_mfa_for_mitigation", False):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Switching to the FRR speaker requires an MFA session")
    if key == "filter_backend" and body.value != get_setting(db, "filter_backend", "simulated"):
        from ..models import MitigationAction, Strategy
        live = db.execute(select(func.count()).select_from(MitigationAction).where(MitigationAction.state.in_(
            ["proposed", "approved", "executing", "active", "withdrawing", "failed"]),
            MitigationAction.strategy == Strategy.LOCAL_FILTER)).scalar_one()
        if live:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"{live} filter actions are still open; withdraw or finish them before switching")
        if body.value == "routeros" and not p.mfa and get_setting(db, "require_mfa_for_mitigation", False):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Filtering on real routers requires an MFA session")
    return _set(db, p, key, body.value, "setting.update")


@router.post("/system/emergency-stop")
def emergency_stop(p: Principal = Depends(require(Perm.AUTOMATION_STOP)), db: Session = Depends(get_db)):
    """Disable all automatic mitigation and block new RTBH announcements. Does NOT withdraw
    existing routes (withdrawing during an attack could re-expose the network)."""
    _set(db, p, "automation_enabled", False, "system.emergency_stop")
    _set(db, p, "rtbh_emergency_disable", True, "system.emergency_stop")
    return {"automation_enabled": False, "rtbh_emergency_disable": True}


@router.post("/system/production")
def set_production(enabled: bool, p: Principal = Depends(require(Perm.AUTOMATION_STOP)), db: Session = Depends(get_db)):
    """Production BGP sessions on or off.

    On: administrators only, signed in with two-factor, with the FRR speaker selected and no
    emergency stop. Each production session still needs a passed acceptance run before it carries
    real blackholes.
    Off: any NOC operator. Every open mitigation is withdrawn (or cancelled) and Shield's
    production sessions are removed from FRR. This is the full rollback."""
    from ..mitigation import service
    from ..models import MitigationAction
    from ..rbac import has_perm
    if enabled:
        if not has_perm(p.user.role, Perm.MANAGE_SETTINGS):
            raise HTTPException(403, "Only administrators can turn production announcements on")
        if not p.mfa:
            raise HTTPException(403, "Turning production announcements on requires a session signed in with "
                                     "two-factor authentication (Settings, My account)")
        if get_setting(db, "bgp_speaker", "simulated") != "frr":
            raise HTTPException(409, "Select the FRR speaker first (bgp_speaker setting)")
        if get_setting(db, "rtbh_emergency_disable", False):
            raise HTTPException(409, "The emergency stop is on; clear it first")
        _set(db, p, "bgp_production_enabled", True, "system.production_on")
        return {"bgp_production_enabled": True, "withdrawn": 0}
    n = 0
    for a in db.execute(select(MitigationAction).where(MitigationAction.state.in_(
            ["proposed", "approved", "executing", "active", "failed"])).with_for_update()).scalars():
        try:
            service.withdraw(db, a, actor=p.user.username, user_id=p.user.id, reason="production announcements switched off")
            n += 1
        except service.Conflict:
            pass
    _set(db, p, "bgp_production_enabled", False, "system.production_off")
    return {"bgp_production_enabled": False, "withdrawn": n}


@router.post("/system/automation")
def set_automation(enabled: bool, rtbh_enabled: bool | None = None,
                   p: Principal = Depends(require(Perm.AUTOMATION_ENABLE)), db: Session = Depends(get_db)):
    _set(db, p, "automation_enabled", enabled, "system.automation_toggle")
    if rtbh_enabled is not None:
        _set(db, p, "rtbh_emergency_disable", not rtbh_enabled, "system.automation_toggle")
    return {"automation_enabled": enabled,
            "rtbh_emergency_disable": get_setting(db, "rtbh_emergency_disable", False)}
