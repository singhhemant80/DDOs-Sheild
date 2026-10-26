"""Router (MikroTik) inventory and read-only RouterOS status (Phase 5).

Connections made from here (test, certificate) are read-only: the client refuses anything but
print commands. Credentials are decrypted server-side only and never returned.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, security
from ..changes import get_setting, record_change
from ..db import get_db
from ..deps import Principal, require
from ..mikrotik import api as ros
from ..mikrotik.poller import probe
from ..models import AccessMode, Router, RouterEvent, RouterState
from ..rbac import Perm
from ..schemas import RouterCreate, RouterOut, RouterUpdate

router = APIRouter(prefix="/routers", tags=["routers"])


def _out(r: Router) -> RouterOut:
    o = RouterOut.model_validate(r)
    o.has_api_password = bool(r.api_password_enc)
    o.has_filter_password = bool(r.filter_password_enc)
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


def _state_out(st: RouterState | None, detail: bool = True) -> dict | None:
    if st is None:
        return None
    out = {"router_id": st.router_id, "polled_at": st.polled_at, "ok": st.ok, "error": st.error,
           "consecutive_failures": st.consecutive_failures, "identity": st.identity, "version": st.version,
           "board": st.board, "uptime_seconds": st.uptime_seconds, "cpu_load": st.cpu_load,
           "resources": st.resources or {},
           "checks": st.checks or [],
           "bgp": st.bgp or []}
    if detail:
        out.update(interfaces=st.interfaces or [], addresses=st.addresses or [], routes=(st.routes or {}).get("items", []),
                   traffic_flow=st.traffic_flow or {}, permissions=st.permissions or {})
    return out


def _event_out(e: RouterEvent, name: str | None = None) -> dict:
    return {"id": e.id, "router_id": e.router_id, "router": name, "at": e.at, "kind": e.kind,
            "severity": e.severity.value, "message": e.message, "detail": e.detail}


@router.get("/states")
def list_states(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Summary of the latest poll of every router (no interface/route detail)."""
    return [_state_out(st, detail=False) for st in db.execute(select(RouterState)).scalars()]


@router.get("/events")
def recent_events(limit: int = Query(100, ge=1, le=1000), _: Principal = Depends(require(Perm.VIEW)),
                  db: Session = Depends(get_db)):
    rows = db.execute(select(RouterEvent, Router.name).join(Router, Router.id == RouterEvent.router_id)
                      .order_by(RouterEvent.at.desc(), RouterEvent.id.desc()).limit(limit)).all()
    return [_event_out(e, n) for e, n in rows]


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
    fuser = data.pop("filter_username", None)
    fpw = data.pop("filter_password", None)
    for k, v in data.items():
        if v is not None:
            setattr(r, k, v)
    if pw:
        r.api_password_enc = _encrypt(pw)
    if data.get("tls_fingerprint") == "":
        r.tls_fingerprint = None
    if fuser == "":
        if _open_filters(db, r.id):
            raise HTTPException(409, "Withdraw this router's active filters before removing its filter account")
        r.filter_username, r.filter_password_enc = None, None
        r.access_mode = AccessMode.READ_ONLY
    elif fuser is not None or fpw:
        if fuser is not None:
            if fuser == r.api_username:
                raise HTTPException(422, "Use a separate account for filtering; the polling account stays read-only")
            r.filter_username = fuser
        if fpw:
            r.filter_password_enc = _encrypt(fpw)
        if not (r.filter_username and r.filter_password_enc):
            raise HTTPException(422, "The filter account needs a username and a password")
        r.access_mode = AccessMode.READ_WRITE
    if r.access_mode == AccessMode.READ_WRITE and not (r.use_tls and (r.verify_tls or r.tls_fingerprint)):
        raise HTTPException(422, "Changing a router (filter account) needs TLS with a verified or pinned certificate")
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


def _open_filters(db: Session, router_id: int) -> bool:
    from ..models import MitigationAction, Strategy
    return db.execute(select(MitigationAction.id).where(
        MitigationAction.router_id == router_id, MitigationAction.strategy == Strategy.LOCAL_FILTER,
        MitigationAction.state.in_(["approved", "executing", "active", "withdrawing", "failed"]))).first() is not None


def _get(db: Session, router_id: int) -> Router:
    r = db.get(Router, router_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Router not found")
    return r


@router.get("/{router_id}/state")
def router_state(router_id: int, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    _get(db, router_id)
    return _state_out(db.get(RouterState, router_id))


@router.get("/{router_id}/events")
def router_events(router_id: int, limit: int = Query(100, ge=1, le=1000),
                  _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    r = _get(db, router_id)
    rows = db.execute(select(RouterEvent).where(RouterEvent.router_id == router_id)
                      .order_by(RouterEvent.at.desc(), RouterEvent.id.desc()).limit(limit)).scalars()
    return [_event_out(e, r.name) for e in rows]


@router.post("/{router_id}/certificate")
def router_certificate(router_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                       db: Session = Depends(get_db)):
    """Read the certificate the router's api-ssl presents. No credentials are sent. Compare the
    fingerprint with `/certificate print detail` on the router before pinning it."""
    r = _get(db, router_id)
    if not r.use_tls:
        raise HTTPException(422, "This router is configured for the plain API; enable TLS first")
    try:
        info = ros.fetch_certificate(str(r.mgmt_address), r.api_port)
    except ros.RouterOSError as e:
        raise HTTPException(502, str(e)) from None
    info.pop("fingerprint_hex", None)
    info["pinned"] = r.tls_fingerprint
    info["matches_pin"] = r.tls_fingerprint == info["fingerprint"] if r.tls_fingerprint else None
    return info


FILTER_NEEDS = {"read", "write", "api"}
FILTER_TOO_MUCH = {"policy", "password", "sensitive", "reboot", "ssh", "telnet", "ftp", "winbox", "web", "local",
                   "sniff", "romon", "rest-api"}


@router.post("/{router_id}/filter-test")
def test_filter_account(router_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                        db: Session = Depends(get_db)):
    """Log in with the filter account and read (never change) what local filtering needs: the
    account's permissions, Shield's rules and the jump rule in the firewall raw table."""
    from ..mikrotik.filterapi import RAW, FilterClient
    r = _get(db, router_id)
    if not (r.filter_username and r.filter_password_enc):
        raise HTTPException(422, "Set the filter account first")
    try:
        password = security.decrypt_secret(r.filter_password_enc)
    except Exception:
        raise HTTPException(503, "The stored filter password cannot be decrypted; enter it again") from None
    checks: list[dict] = []
    try:
        with FilterClient(str(r.mgmt_address), r.api_port, r.filter_username, password, use_tls=r.use_tls,
                          verify_tls=r.verify_tls, fingerprint=r.tls_fingerprint) as c:
            users = c.print("/user", queries=[f"name={r.filter_username}"])
            group = users[0].get("group") if users else None
            groups = c.print("/user/group", queries=[f"name={group}"]) if group else []
            policy = {x for x in (groups[0].get("policy", "") if groups else "").split(",") if x and not x.startswith("!")}
            rules = c.shield_rules(4)
            raw_total = c.count(RAW[4])
        missing = FILTER_NEEDS - policy
        extra = sorted(policy & FILTER_TOO_MUCH)
        if missing:
            checks.append({"level": "error", "code": "filter_perm",
                           "message": f"The account's group ({group}) lacks: {', '.join(sorted(missing))}."})
        else:
            checks.append({"level": "ok", "code": "filter_perm", "message": f"Group {group} may read, write and use the API."})
        if extra:
            checks.append({"level": "warn", "code": "filter_extra",
                           "message": f"The group also allows {', '.join(extra)}; remove what Shield does not need "
                                      "(it needs only read, write, api)."})
        jump = any(x.get("comment") == "shield:jump" for x in rules)
        checks.append({"level": "ok", "code": "filter_rules",
                       "message": f"Firewall raw has {raw_total} rules, {len(rules)} of them Shield's"
                                  + ("" if jump else "; the shield-filter jump is added with the first filter") + "."})
        result = {"ok": not missing, "checks": checks, "group": group, "policy": sorted(policy)}
    except ros.TLSUntrusted as e:
        result = {"ok": False, "kind": e.kind, "error": str(e)}
    except ros.RouterOSError as e:
        result = {"ok": False, "kind": e.kind, "error": str(e)}
    audit.record(db, p.actor, "router.filter_test", "router", router_id, after={"ok": result["ok"]})
    return result


@router.post("/{router_id}/test")
def test_router(router_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    """Connect once with the stored credentials, read everything Shield polls (read-only), and
    return the checks, including whether the account could change the router."""
    r = _get(db, router_id)
    if not (r.api_username and r.api_password_enc):
        raise HTTPException(422, "Set the API username and password first")
    try:
        password = security.decrypt_secret(r.api_password_enc)
    except Exception:
        raise HTTPException(503, "The stored password cannot be decrypted (SHIELD_CREDENTIAL_KEY changed?); "
                                 "enter it again") from None
    collector = get_setting(db, "collector_address", "") or None
    result: dict = {"ok": False}
    try:
        snap = probe(str(r.mgmt_address), r.api_port, r.api_username, password, use_tls=r.use_tls,
                     verify_tls=r.verify_tls, fingerprint=r.tls_fingerprint, mgmt=str(r.mgmt_address),
                     collector=collector, model=r.model.value)
        result = {"ok": True, "tls": snap["tls"], "system": snap.get("system"), "checks": snap["checks"],
                  "permissions": snap.get("permissions"), "bgp": snap["bgp_peers"],
                  "interfaces": len(snap.get("interfaces") or []), "errors": snap.get("errors")}
    except ros.TLSUntrusted as e:
        result = {"ok": False, "kind": e.kind, "error": str(e),
                  "presented_fingerprint": ros.colon_fingerprint(e.fingerprint) if e.fingerprint else None}
    except ros.RouterOSError as e:
        result = {"ok": False, "kind": e.kind, "error": str(e)}
    audit.record(db, p.actor, "router.test", "router", router_id,
                 after={"ok": result["ok"], "kind": result.get("kind"), "tls": result.get("tls")})
    return result
