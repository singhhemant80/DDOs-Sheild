"""BGP sessions: the neighbour inventory, live state (routers via RouterOS from Phase 5, Shield's
own FRR speaker from Phase 7), and the receive filter your routers need for Shield's blackholes."""
from __future__ import annotations

import ipaddress
import json

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, security
from .. import telemetry as tm
from ..changes import get_setting, record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import (
    AcceptanceRun, BgpNeighbor, BgpPurpose, CustomerIpAssignment, ProtectedPrefix, Router, RouterState, UpstreamProvider,
)
from ..rbac import Perm
from ..schemas import BgpNeighborCreate, BgpNeighborOut, BgpNeighborUpdate

router = APIRouter(prefix="/bgp", tags=["bgp"])


def _out(n: BgpNeighbor) -> BgpNeighborOut:
    o = BgpNeighborOut.model_validate(n)
    o.has_md5_password = bool(n.md5_password_enc)
    return o


def _encrypt(pw: str) -> str:
    try:
        return security.encrypt_secret(pw)
    except security.CredentialKeyMissing:
        raise HTTPException(503, "SHIELD_CREDENTIAL_KEY is not configured; cannot store BGP passwords") from None


@router.get("/neighbors", response_model=list[BgpNeighborOut])
def list_neighbors(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return [_out(n) for n in db.execute(select(BgpNeighbor).order_by(BgpNeighbor.name)).scalars()]


def _speaker_peers() -> dict[str, dict]:
    try:
        st = json.loads(tm.rds().get("shield:mitigator:status") or "null") or {}
    except Exception:
        return {}
    peers = st.get("peers")
    return {p["address"]: p for p in peers} if isinstance(peers, list) else {}


@router.get("/sessions")
def live_sessions(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """BGP sessions as last read from each router and from Shield's own speaker, matched to the
    neighbour inventory. `in_inventory` is false for sessions on a router but not recorded in Shield."""
    inv = {(n.router_id, str(n.neighbor_address)): n for n in db.execute(select(BgpNeighbor)).scalars()}
    names = dict(db.execute(select(Router.id, Router.name)).all())
    out = []
    for st, name in db.execute(select(RouterState, Router.name).join(Router, Router.id == RouterState.router_id)):
        for peer in st.bgp or []:
            n = inv.pop((st.router_id, peer.get("remote_address")), None)
            out.append({**peer, "router_id": st.router_id, "router": name, "polled_at": st.polled_at,
                        "stale": not st.ok, "in_inventory": n is not None, "neighbor_id": n.id if n else None,
                        "purpose": n.purpose.value if n else None})
    speaker = _speaker_peers()
    for (rid, addr), n in inv.items():
        if rid is not None:
            out.append({"name": n.name, "remote_address": addr, "remote_as": n.remote_asn, "router_id": rid,
                        "router": names.get(rid), "state": n.last_state or "unknown", "established": False,
                        "in_inventory": True, "neighbor_id": n.id, "purpose": n.purpose.value,
                        "missing_on_router": n.last_state == "not_configured", "stale": True})
        else:
            sp = speaker.get(addr)
            out.append({"name": n.name, "remote_address": addr, "remote_as": n.remote_asn, "router_id": None,
                        "router": "Shield", "shield": True, "state": (sp or {}).get("state") or "not running",
                        "established": (sp or {}).get("state") == "Established", "prefixes_sent": (sp or {}).get("prefixes_sent"),
                        "uptime": (sp or {}).get("uptime"), "environment": n.environment,
                        "acceptance_passed_at": n.acceptance_passed_at,
                        "peer": "internal" if n.purpose == BgpPurpose.RTBH_SIGNAL else f"upstream:{n.upstream_id}",
                        "in_inventory": True, "neighbor_id": n.id, "purpose": n.purpose.value,
                        "managed_by_shield": n.managed_by_shield, "stale": sp is None})
    return out


@router.post("/neighbors", response_model=BgpNeighborOut, status_code=201)
def create_neighbor(body: BgpNeighborCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    if body.router_id is not None and db.get(Router, body.router_id) is None:
        raise HTTPException(422, "router_id does not exist")
    if body.upstream_id is not None:
        up = db.get(UpstreamProvider, body.upstream_id)
        if up is None:
            raise HTTPException(422, "upstream_id does not exist")
        if up.asn != body.remote_asn:
            raise HTTPException(422,
                                f"remote_asn {body.remote_asn} does not match upstream ASN {up.asn}")
    data = body.model_dump(exclude={"md5_password"})
    n = BgpNeighbor(**data)
    if body.md5_password:
        n.md5_password_enc = _encrypt(body.md5_password)
    db.add(n)
    record_change(db, p.actor, "bgp_neighbor.create", "bgp_neighbor", n)
    return _out(n)


@router.patch("/neighbors/{neighbor_id}", response_model=BgpNeighborOut)
def update_neighbor(neighbor_id: int, body: BgpNeighborUpdate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    n = db.get(BgpNeighbor, neighbor_id)
    if n is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Neighbor not found")
    before = audit.snapshot(n)
    data = body.model_dump(exclude_unset=True)
    pw = data.pop("md5_password", None)
    if data.get("environment") == "production" and n.environment != "production":
        # Recorded now; the speaker does not configure production sessions until phase 8.
        if not p.mfa and get_setting(db, "require_mfa_for_mitigation", False):
            raise HTTPException(403, "Marking a session production requires an MFA session")
    changed = {k for k, v in data.items() if getattr(n, k) != v} | ({"md5_password"} if pw is not None else set())
    for k, v in data.items():
        setattr(n, k, v)
    if pw is not None:
        n.md5_password_enc = _encrypt(pw) if pw else None
    # Anything that changes where or how routes are sent invalidates the acceptance run.
    if changed & {"environment", "remote_port", "ebgp_multihop", "local_address", "md5_password", "max_prefix_out"}:
        n.acceptance_passed_at = None
    record_change(db, p.actor, "bgp_neighbor.update", "bgp_neighbor", n, before=before)
    return _out(n)


@router.delete("/neighbors/{neighbor_id}", status_code=204)
def delete_neighbor(neighbor_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    n = db.get(BgpNeighbor, neighbor_id)
    if n is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Neighbor not found")
    before = audit.snapshot(n)
    db.delete(n)
    record_change(db, p.actor, "bgp_neighbor.delete", "bgp_neighbor", None, entity_id=neighbor_id, before=before)


# ---------------------------------------------------------------- receive filter for your routers
def receive_filter(db: Session, fmt: str, shield_address: str | None = None) -> str:
    """The filter a router needs on its session from Shield: accept only blackhole routes for
    protected prefixes that allow blackholing, no broader than each prefix permits, carrying the
    internal blackhole community; reject everything else."""
    comm = get_setting(db, "internal_blackhole_community", "")
    if not comm:
        raise HTTPException(409, "Set internal_blackhole_community first")
    rows = db.execute(select(ProtectedPrefix).where(ProtectedPrefix.enabled, ProtectedPrefix.rtbh_allowed,
                                                    ProtectedPrefix.ownership_verified)
                      .order_by(ProtectedPrefix.prefix)).scalars().all()
    shield = db.execute(select(BgpNeighbor).where(BgpNeighbor.router_id.is_(None),
                                                  BgpNeighbor.purpose == BgpPurpose.RTBH_SIGNAL)).scalars().first()
    asn = shield.local_asn if shield else "<shield-asn>"
    router_asn = shield.remote_asn if shield else "<your-asn>"
    addr = shield_address or (str(shield.local_address) if shield and shield.local_address else "<shield-address>")
    nets = [(ipaddress.ip_network(str(p.prefix)), p.min_mitigation_prefix_len) for p in rows]
    if fmt == "frr":
        out = ["! Crapplet Shield: accept blackhole routes from Shield only for authorised prefixes.",
               "! Generated from the protected prefix list; regenerate after changing prefixes.", "!"]
        for i, (net, minlen) in enumerate(nets, 1):
            fam = "ip" if net.version == 4 else "ipv6"
            rng = f" ge {minlen}" if minlen > net.prefixlen else f" le {net.prefixlen}"
            out.append(f"{fam} prefix-list SHIELD-PROTECTED{'' if net.version == 4 else '-V6'} seq {i * 5} permit {net}{rng}")
        out += [f"bgp community-list standard SHIELD-BLACKHOLE seq 5 permit {comm}", "!",
                "route-map FROM-SHIELD permit 10", " match ip address prefix-list SHIELD-PROTECTED",
                " match community SHIELD-BLACKHOLE", " set ip next-hop 192.0.2.1", "exit",
                "route-map FROM-SHIELD permit 20", " match ipv6 address prefix-list SHIELD-PROTECTED-V6",
                " match community SHIELD-BLACKHOLE", "exit",
                "route-map FROM-SHIELD deny 100", "exit", "route-map TO-SHIELD deny 10", "exit", "!",
                "! router bgp <your-asn>", f"!  neighbor {addr} remote-as {asn}",
                "!  address-family ipv4 unicast",
                f"!   neighbor {addr} route-map FROM-SHIELD in", f"!   neighbor {addr} route-map TO-SHIELD out",
                f"!   neighbor {addr} maximum-prefix 100",
                "! and route the discard next hop to null: ip route 192.0.2.1/32 Null0"]
        return "\n".join(out) + "\n"
    # RouterOS v7
    out = ["# Crapplet Shield: accept blackhole routes from Shield only for authorised prefixes.",
           "# RouterOS 7. Generated from the protected prefix list; regenerate after changing prefixes.",
           "# Review before importing, and run in Safe Mode. Verify on your RouterOS version.",
           "/routing/filter/rule"]
    for net, minlen in nets:
        cond = f"dst in {net} && dst-len >= {max(minlen, net.prefixlen)}"
        out.append(f'add chain=shield-rtbh-in rule="if ({cond} && bgp-communities includes {comm}) '
                   f'{{ set blackhole yes; accept }}" comment="Shield: {net}"')
    out += ['add chain=shield-rtbh-in rule="reject" comment="Shield: everything else"',
            'add chain=shield-rtbh-out rule="reject" comment="Shield: send nothing to Shield"',
            "# RouterOS 7.20 and later: the session belongs to the router's existing BGP instance for",
            f"# AS{router_asn} (the one its upstream sessions use). Checked on RouterOS 7.25.",
            "{",
            f":local inst [/routing/bgp/instance find where as={router_asn}]",
            f':if ([:len $inst] = 0) do={{ :error "No BGP instance with AS {router_asn}: see /routing/bgp/instance/print" }}',
            f"/routing/bgp/connection add name=shield-rtbh instance=[/routing/bgp/instance get ($inst->0) name] "
            f"remote.address={addr} remote.as={asn} local.role=ibgp multihop=yes "
            "input.filter=shield-rtbh-in output.filter-chain=shield-rtbh-out input.limit-process-routes-ipv4=100 "
            'comment="Crapplet Shield blackhole signalling"',
            "}",
            "# RouterOS 7.19 and earlier have no BGP instances; there use instead:",
            f"# /routing/bgp/connection add name=shield-rtbh as={router_asn} remote.address={addr} remote.as={asn} "
            "local.role=ibgp multihop=yes input.filter=shield-rtbh-in output.filter-chain=shield-rtbh-out "
            'input.limit-process-routes-ipv4=100 comment="Crapplet Shield blackhole signalling"']
    return "\n".join(out) + "\n"


@router.get("/receive-filter", response_class=PlainTextResponse)
def get_receive_filter(fmt: str = Query("routeros", alias="format", pattern="^(routeros|frr)$"),
                       _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return receive_filter(db, fmt)


# ---------------------------------------------------------------- acceptance runs (Phase 8)
class AcceptanceIn(BaseModel):
    peer: str = Field(pattern=r"^(internal|upstream:[0-9]{1,9})$")
    target: str = Field(max_length=64)
    confirm_unused: bool = False


def _run_out(r: AcceptanceRun) -> dict:
    return {"id": str(r.id), "peer": r.peer, "target": str(r.target), "status": r.status, "step": r.step,
            "action_id": str(r.action_id) if r.action_id else None, "started_at": r.started_at,
            "finished_at": r.finished_at, "steps": r.steps or [], "error": r.error}


@router.post("/acceptance", status_code=201)
def start_acceptance(body: AcceptanceIn, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                     db: Session = Depends(get_db)):
    """Start an acceptance run: a canary blackhole for an unused address of yours over one peer,
    proving that nothing else changes. Production sessions carry real blackholes only after one passes."""
    from .. import netvalidate as nv
    if get_setting(db, "bgp_speaker", "simulated") != "frr":
        raise HTTPException(409, "Acceptance runs need the FRR speaker (bgp_speaker setting)")
    if not body.confirm_unused:
        raise HTTPException(422, "Confirm that the canary address is not in use: it will be unreachable during the run")
    try:
        net = nv.parse_target(body.target)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if net.num_addresses != 1:
        raise HTTPException(422, "The canary must be a single address")
    from sqlalchemy import cast
    from sqlalchemy.dialects.postgresql import CIDR
    if db.execute(select(CustomerIpAssignment).where(cast(str(net), CIDR).op("<<=")(CustomerIpAssignment.address))).first():
        raise HTTPException(422, "That address is assigned to a customer; choose an unused one")
    q = select(BgpNeighbor).where(BgpNeighbor.router_id.is_(None), BgpNeighbor.managed_by_shield, BgpNeighbor.enabled)
    q = q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_SIGNAL) if body.peer == "internal" else \
        q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_UPSTREAM, BgpNeighbor.upstream_id == int(body.peer.split(":")[1]))
    sessions = db.execute(q).scalars().all()
    if not sessions:
        raise HTTPException(422, "Shield has no enabled session for that peer")
    if any(n.environment == "production" for n in sessions) and not get_setting(db, "bgp_production_enabled", False):
        raise HTTPException(409, "Turn production announcements on first (Settings)")
    if db.execute(select(AcceptanceRun).where(AcceptanceRun.peer == body.peer,
                                              AcceptanceRun.status.in_(["pending", "running"]))).first():
        raise HTTPException(409, "An acceptance run for this peer is already in progress")
    run = AcceptanceRun(id=uuid.uuid4(), peer=body.peer, target=str(net), status="pending", step="pending",
                        started_by_id=p.user.id, baseline={}, steps=[])
    db.add(run)
    db.flush()
    audit.record(db, p.actor, "acceptance.start", "acceptance_run", run.id,
                 after={"peer": body.peer, "target": str(net)})
    return _run_out(run)


@router.get("/acceptance")
def list_acceptance(peer: str | None = None, limit: int = Query(20, ge=1, le=200),
                    _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(AcceptanceRun).order_by(AcceptanceRun.started_at.desc()).limit(limit)
    if peer:
        q = q.where(AcceptanceRun.peer == peer)
    return [_run_out(r) for r in db.execute(q).scalars()]


@router.get("/acceptance/{run_id}")
def get_acceptance(run_id: uuid.UUID, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    r = db.get(AcceptanceRun, run_id)
    if r is None:
        raise HTTPException(404, "Acceptance run not found")
    return _run_out(r)
