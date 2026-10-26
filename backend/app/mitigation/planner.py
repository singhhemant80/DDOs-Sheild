"""Builds a mitigation plan: exactly which routes would be announced, every safety check with its
result, and the impact in plain language. Planning never changes anything; the same function runs
at preview, at proposal, again at approval, and again just before execution, so a plan that was
safe ten minutes ago is not executed if something changed since.

Checks have a level:
  block - the action cannot be proposed or executed
  warn  - allowed, but the operator must read it (automatic actions treat some warnings as blocks)
  ok    - passed; listed so the operator can see what was checked
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import cast, func, select, true
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import netvalidate as nv
from .. import telemetry as tm
from ..changes import get_setting
from ..models import (
    ActionState, BgpNeighbor, CustomerIpAssignment, MitigationAction, ProtectedPrefix, Router, RtbhRoute,
    RtbhStatus, ServiceType, Strategy, UpstreamProvider,
)

LIVE_ACTION_STATES = ("proposed", "approved", "executing", "active", "withdrawing")
LIVE_ROUTE_STATES = (RtbhStatus.PENDING_ANNOUNCE, RtbhStatus.ANNOUNCED, RtbhStatus.VERIFIED, RtbhStatus.WITHDRAWING)
RTBH_STRATEGIES = (Strategy.RTBH_UPSTREAM.value, Strategy.RTBH_INTERNAL.value)
FILTER_STRATEGIES = (Strategy.LOCAL_FILTER.value,)
AVAILABLE_STRATEGIES = RTBH_STRATEGIES + FILTER_STRATEGIES


@dataclass
class PlanRequest:
    target: str
    strategy: str = Strategy.RTBH_UPSTREAM.value
    upstream_ids: list[int] | None = None       # None: the default set (see _choose_upstreams)
    incident_id: str | None = None
    duration_seconds: int | None = None
    automatic: bool = False          # proposed by a policy: stricter checks
    auto_approve: bool = False       # will run without a person approving: needs the automation switch
    exclude_action_ids: list[str] = field(default_factory=list)   # re-checking an existing action
    acceptance_peer: str | None = None   # Phase 8: canary of an acceptance run over this peer
    router_ids: list[int] | None = None  # Phase 9 local filtering: None = every enabled router
    filters: list[dict] | None = None    # Phase 9: drop rules; None = derived from the incident's attack types


class Plan(dict):
    @property
    def blocked(self) -> bool:
        return self["blocked"]


def _check(out: list, level: str, code: str, message: str) -> None:
    out.append({"level": level, "code": code, "message": message})


def _peer(upstream_id: int | None) -> str:
    return f"upstream:{upstream_id}" if upstream_id is not None else "internal"


def _choose_upstreams(db: Session, pp: ProtectedPrefix | None) -> list[UpstreamProvider]:
    """Default: every enabled upstream with an enabled blackhole policy. Blackholing at only some
    upstreams leaves the target reachable (and attackable) through the others."""
    rows = db.execute(select(UpstreamProvider).where(UpstreamProvider.enabled).order_by(UpstreamProvider.name)).scalars().all()
    return [u for u in rows if u.rtbh_policy and u.rtbh_policy.enabled]


def _infrastructure_addresses(db: Session) -> dict[str, str]:
    """Addresses Shield must never blackhole: routers and BGP session endpoints."""
    out: dict[str, str] = {}
    for r in db.execute(select(Router)).scalars():
        out[str(r.mgmt_address)] = f"management address of router {r.name}"
    for n in db.execute(select(BgpNeighbor)).scalars():
        out[str(n.neighbor_address)] = f"BGP neighbour {n.name}"
        if n.local_address:
            out[str(n.local_address)] = f"local address of BGP session {n.name}"
    collector = get_setting(db, "collector_address", "")
    if collector:
        out[collector] = "the Shield collector"
    return out


def _session_states() -> dict[str, str]:
    """Session states the controller last reported from FRR (address -> state)."""
    try:
        import json
        st = json.loads(tm.rds().get("shield:mitigator:status") or "null") or {}
    except Exception:
        return {}
    peers = st.get("peers")
    return {p["address"]: p.get("state") or "?" for p in peers} if isinstance(peers, list) else {}


def _speaker_checks(db: Session, routes: list[dict], checks: list, acceptance_peer: str | None = None) -> None:
    """Which of Shield's BGP sessions would carry each route, and whether they may.
    Staging sessions always may. Production sessions may only while production announcements are
    switched on, and only after their acceptance run passed (except for that run's own canary)."""
    from ..models import BgpPurpose
    states = _session_states()
    production_on = bool(get_setting(db, "bgp_production_enabled", False))
    for r in routes:
        q = select(BgpNeighbor).where(BgpNeighbor.router_id.is_(None), BgpNeighbor.managed_by_shield,
                                      BgpNeighbor.enabled)
        if r["upstream_id"] is not None:
            q = q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_UPSTREAM, BgpNeighbor.upstream_id == r["upstream_id"])
            who = r["upstream"]
        else:
            q = q.where(BgpNeighbor.purpose == BgpPurpose.RTBH_SIGNAL)
            who = "your edge routers"
        sessions = db.execute(q).scalars().all()
        staging = [n for n in sessions if n.environment == "staging"]
        prod = [n for n in sessions if n.environment == "production"] if production_on else []
        canary = acceptance_peer == r["peer"]
        unaccepted = [n for n in prod if n.acceptance_passed_at is None]
        usable = staging + prod
        code = f"session_{r['peer']}"
        if not usable:
            if sessions and not production_on:
                _check(checks, "block", code, f"Shield's sessions to {who} are production sessions and production "
                       "announcements are switched off (Settings).")
            else:
                _check(checks, "block", code, f"Shield has no BGP session to {who}. Add one under BGP sessions.")
            continue
        if unaccepted and not canary:
            _check(checks, "block", code,
                   f"Production session(s) to {who} ({', '.join(n.name for n in unaccepted)}) have not passed an "
                   "acceptance run. Run one from BGP sessions first.")
            continue
        down = [f"{n.neighbor_address} ({states.get(str(n.neighbor_address), 'unknown')})" for n in usable
                if states.get(str(n.neighbor_address)) != "Established"]
        kinds = " and ".join(x for x in (f"{len(prod)} production" if prod else "", f"{len(staging)} staging" if staging else "") if x)
        if down:
            _check(checks, "warn", code,
                   f"Session to {who} not established: {', '.join(down)}. The announcement fails unless it comes up.")
        else:
            _check(checks, "ok" if not prod else "warn", code,
                   f"Announced by Shield's BGP speaker over {kinds} session(s) to {who}."
                   + (" This is a real announcement." if prod else ""))


def _live_load(net) -> dict:
    snap = tm.live_snapshot()
    if not snap.get("available"):
        return {"available": False, "reason": snap.get("reason", "no live data")}
    pps = bps = 0.0
    prov = set()
    for d in snap.get("dsts", []):
        try:
            if ipaddress.ip_address(d["ip"]) in net:
                pps += d.get("pps", 0)
                bps += d.get("bps", 0)
                prov.add(d.get("provenance", "sampled"))
        except (ValueError, KeyError):
            continue
    if not prov:
        return {"available": True, "pps": 0, "bps": 0, "provenance": None, "seen": False}
    return {"available": True, "pps": pps, "bps": bps, "seen": True,
            "provenance": "estimated" if "estimated" in prov else "sampled" if "sampled" in prov else "measured"}


def build_plan(db: Session, req: PlanRequest, now: datetime | None = None) -> Plan:
    now = now or datetime.now(UTC)
    checks: list[dict] = []
    routes: list[dict] = []
    impact: list[str] = []
    try:
        net = nv.parse_target(req.target)
    except ValueError as e:
        return Plan(target=req.target, strategy=req.strategy, blocked=True, routes=[], impact={"statements": []},
                    checks=[{"level": "block", "code": "target_invalid", "message": str(e)}], simulation=True)
    target = str(net)
    if req.strategy not in AVAILABLE_STRATEGIES:
        _check(checks, "block", "strategy", f"{req.strategy} is not available yet; blackholing (RTBH) and local "
                                            "filtering are.")
    filtering = req.strategy in FILTER_STRATEGIES

    # --- the protected prefix and the customer -----------------------------------------------
    from ..api.prefixes import eligibility_for  # shared with the eligibility API
    el = eligibility_for(db, net)
    pp = db.get(ProtectedPrefix, el.protected_prefix_id) if el.protected_prefix_id else None
    if pp is None:
        _check(checks, "block", "not_protected", f"{target} is not inside any protected prefix.")
    else:
        if not pp.enabled:
            _check(checks, "block", "prefix_disabled", f"Protected prefix {pp.prefix} is disabled.")
        if not pp.ownership_verified:
            _check(checks, "block", "ownership", f"Ownership of {pp.prefix} has not been verified.")
        if filtering and not pp.filtering_allowed:
            _check(checks, "block", "filtering_not_allowed", f"Local filtering is not enabled for {pp.prefix} "
                                                             "(Protected prefixes → Edit).")
        if not filtering and not pp.rtbh_allowed:
            _check(checks, "block", "rtbh_not_allowed", f"Blackholing is not enabled for {pp.prefix}.")
        if filtering and net.prefixlen < (24 if net.version == 4 else 48):
            _check(checks, "block", "scope", f"Filters apply to a /24 (/48) or smaller, not {target}.")
        elif filtering:
            _check(checks, "ok", "prefix", f"{target} is inside {pp.prefix}; ownership verified; filtering allowed."
                   if pp.enabled and pp.ownership_verified and pp.filtering_allowed else f"{target} is inside {pp.prefix}.")
        elif not el.within_scope_limit:
            _check(checks, "block", "scope",
                   f"{target} is broader than {pp.prefix} allows (/{pp.min_mitigation_prefix_len} or longer). "
                   "Blackholing a whole range for one address needs an explicit prefix policy.")
        elif pp.enabled and pp.ownership_verified and pp.rtbh_allowed:
            _check(checks, "ok", "prefix", f"{target} is inside {pp.prefix}; ownership verified; blackholing allowed.")
    cust = db.execute(select(CustomerIpAssignment).where(
        cast(target, CIDR).op("<<=")(CustomerIpAssignment.address))).scalar_one_or_none()
    if cust is not None and cust.rtbh_opt_out and not filtering:
        _check(checks, "block", "customer_opt_out", f"Customer {cust.customer_ref} has opted out of blackholing.")
    if cust is not None and cust.service_type == ServiceType.INFRA:
        _check(checks, "block" if req.automatic else "warn", "customer_infra",
               f"{target} is marked as infrastructure ({cust.customer_ref}). Blackholing it may cut off services "
               "other customers rely on." + (" Automatic actions never blackhole infrastructure." if req.automatic else ""))
    infra = _infrastructure_addresses(db)
    hits = [f"{a} ({why})" for a, why in infra.items() if ipaddress.ip_address(a) in net]
    if hits and not filtering:
        _check(checks, "block", "own_infrastructure",
               "The target includes Shield's own network: " + "; ".join(hits) + ". Blackholing it would cut off management.")

    # --- global switches ---------------------------------------------------------------------
    if get_setting(db, "rtbh_emergency_disable", False):
        _check(checks, "block", "emergency_stop", "Emergency stop is on: new blackholes and filters are blocked.")
    if hits and filtering:
        _check(checks, "block" if req.automatic else "warn", "own_infrastructure",
               "The target includes Shield's own network: " + "; ".join(hits) + ". Check the filter cannot cut off "
               "management." + (" Automatic actions never filter it." if req.automatic else ""))
    if req.auto_approve and not get_setting(db, "automation_enabled", False):
        _check(checks, "block", "automation_off", "Automatic mitigation is turned off.")

    # --- routes ------------------------------------------------------------------------------
    exclude = [str(x) for x in req.exclude_action_ids]
    if req.strategy == Strategy.RTBH_UPSTREAM.value:
        all_ups = db.execute(select(UpstreamProvider).where(UpstreamProvider.enabled).order_by(UpstreamProvider.name)).scalars().all()
        chosen = ([u for u in all_ups if u.id in set(req.upstream_ids)] if req.upstream_ids is not None
                  else _choose_upstreams(db, pp))
        if req.upstream_ids is not None:
            missing = set(req.upstream_ids) - {u.id for u in chosen}
            for m in sorted(missing):
                _check(checks, "block", "upstream_unknown", f"Upstream {m} does not exist or is disabled.")
        if not chosen:
            _check(checks, "block", "no_upstream", "No upstream has an enabled, verified blackhole policy.")
        for u in chosen:
            pol = u.rtbh_policy
            if pol is None or not pol.enabled or not pol.verified_at:
                _check(checks, "block", "policy", f"{u.name} has no enabled, verified blackhole policy.")
                continue
            if not (pol.min_prefix_len <= net.prefixlen <= pol.max_prefix_len):
                _check(checks, "block", "policy_length",
                       f"{u.name} accepts blackholes from /{pol.min_prefix_len} to /{pol.max_prefix_len}; {target} is /{net.prefixlen}.")
                continue
            in_use = db.execute(select(func.count()).select_from(RtbhRoute).where(
                RtbhRoute.upstream_id == u.id, RtbhRoute.status.in_(LIVE_ROUTE_STATES),
                ~RtbhRoute.action_id.in_(exclude) if exclude else true())).scalar_one()
            if in_use + 1 > pol.max_routes:
                _check(checks, "block", "upstream_limit",
                       f"{u.name} allows {pol.max_routes} blackhole routes and {in_use} are in use.")
                continue
            comms = list(pol.communities)
            desc = [f"announce {target} to {u.name} (AS{u.asn})"]
            if comms:
                desc.append("communities " + ", ".join(comms))
            if pol.add_no_export:
                desc.append("no-export")
            if pol.next_hop:
                desc.append(f"next-hop {pol.next_hop}")
            routes.append({"peer": _peer(u.id), "upstream_id": u.id, "upstream": u.name, "asn": u.asn, "prefix": target,
                           "communities": comms, "next_hop": str(pol.next_hop) if pol.next_hop else None,
                           "no_export": pol.add_no_export, "description": ", ".join(desc)})
            _check(checks, "ok", f"policy_{u.id}",
                   f"{u.name}: verified policy ({pol.documentation_ref}), {in_use} of {pol.max_routes} routes in use.")
        others = [u for u in all_ups if u.id not in {r["upstream_id"] for r in routes}]
        if routes:
            names = ", ".join(r["upstream"] for r in routes)
            impact.append(f"All traffic to {target} will be dropped by {names}, legitimate traffic included: "
                          f"the address becomes unreachable through {'that provider' if len(routes) == 1 else 'those providers'}.")
        if others and routes:
            impact.append(f"Traffic arriving through {', '.join(u.name for u in others)} is not blackholed and still reaches {target}.")
            _check(checks, "warn", "partial_coverage",
                   f"Not blackholed at {', '.join(u.name for u in others)}: attack traffic through "
                   f"{'it' if len(others) == 1 else 'them'} continues.")
    elif req.strategy == Strategy.RTBH_INTERNAL.value:
        comm = get_setting(db, "internal_blackhole_community", "")
        if not comm:
            _check(checks, "block", "internal_not_configured", "Internal blackholing needs the internal_blackhole_community setting.")
        else:
            routes.append({"peer": "internal", "upstream_id": None, "upstream": None, "asn": None, "prefix": target,
                           "communities": [comm], "next_hop": None, "no_export": True,
                           "description": f"announce {target} to your own edge routers with community {comm}, no-export"})
            impact.append(f"Your edge routers drop all traffic to {target}, legitimate traffic included.")
            _check(checks, "warn", "internal_capacity",
                   "Internal blackholing drops traffic at your edge after it has crossed the upstream links. "
                   "It does not relieve a saturated upstream link; use upstream blackholing for that.")

    elif filtering:
        from .filtering import _filter_plan
        _filter_plan(db, req, net, target, routes, checks, impact)

    # --- the BGP speaker ---------------------------------------------------------------------
    speaker = get_setting(db, "bgp_speaker", "simulated")
    if speaker == "frr" and routes and not filtering:
        _speaker_checks(db, routes, checks, req.acceptance_peer)

    # --- limits and conflicts ----------------------------------------------------------------
    live_q = select(func.count()).select_from(RtbhRoute).where(RtbhRoute.status.in_(LIVE_ROUTE_STATES))
    if exclude:
        live_q = live_q.where(~RtbhRoute.action_id.in_(exclude))
    live = db.execute(live_q).scalar_one()
    cap = int(get_setting(db, "global_max_rtbh_routes", 50))
    if live + len(routes) > cap and not filtering:
        _check(checks, "block", "global_limit", f"{live} blackhole routes are in use; this needs {len(routes)} more and the limit is {cap}.")
    conflict_q = select(MitigationAction).where(
        MitigationAction.state.in_(LIVE_ACTION_STATES), MitigationAction.strategy == req.strategy,
        cast(target, CIDR) == MitigationAction.target)
    if exclude:
        conflict_q = conflict_q.where(~MitigationAction.id.in_(exclude))
    for a in db.execute(conflict_q).scalars():
        if filtering:
            if any(r.get("router_id") == a.router_id for r in routes):
                _check(checks, "block", "duplicate", f"{target} already has a {a.state.value} filter on this router "
                                                     f"({str(a.id)[:8]}). Withdraw it first to change the rules.")
        elif a.upstream_id is None or any(r["upstream_id"] == a.upstream_id for r in routes):
            _check(checks, "block", "duplicate", f"{target} already has a {a.state.value} action ({str(a.id)[:8]}).")

    cooldown = int(get_setting(db, "rtbh_flap_cooldown_seconds", 900))
    recent = None if filtering else db.execute(select(func.max(MitigationAction.completed_at)).where(
        MitigationAction.state == ActionState.WITHDRAWN,
        cast(target, CIDR) == MitigationAction.target,
        MitigationAction.completed_at >= now - timedelta(seconds=cooldown))).scalar()
    if recent:
        mins = max(1, int((now - recent).total_seconds() // 60))
        _check(checks, "block" if req.automatic else "warn", "flap",
               f"{target} was un-blackholed {mins} min ago. Re-blackholing within {cooldown // 60} min "
               + ("needs a person." if req.automatic else "can make the address flap; check the attack is really back."))

    if net.num_addresses > 1:
        impact.append(f"{net.num_addresses} addresses are affected, not one.")
        _check(checks, "warn", "range", f"{target} covers {net.num_addresses} addresses.")
    if pp is not None and routes:
        impact.append(f"No other address in {pp.prefix} is affected.")
    if cust and not filtering:
        impact.append(f"Customer {cust.customer_ref}{f' ({cust.customer_name})' if cust.customer_name else ''}, "
                      f"{cust.service_type.value}, loses all connectivity on {target} for the duration.")
    elif cust:
        impact.append(f"Customer {cust.customer_ref}{f' ({cust.customer_name})' if cust.customer_name else ''} keeps "
                      "all traffic except what the filters drop.")

    duration = req.duration_seconds or int(get_setting(db, "rtbh_default_duration_minutes", 60)) * 60
    blocked = any(c["level"] == "block" for c in checks)
    return Plan(
        target=target, strategy=req.strategy, blocked=blocked, routes=routes, checks=checks,
        duration_seconds=duration, protected_prefix_id=pp.id if pp else None,
        simulation=(get_setting(db, "filter_backend", "simulated") != "routeros") if filtering else speaker != "frr",
        speaker=get_setting(db, "filter_backend", "simulated") if filtering else speaker,
        acceptance_peer=req.acceptance_peer,
        impact={"statements": impact, "addresses": net.num_addresses, "live": _live_load(net),
                "customer": el.customer},
    )
