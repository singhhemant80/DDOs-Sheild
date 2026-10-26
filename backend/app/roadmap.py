"""Delivery roadmap shown on the dashboard: which phases are built, which is current, which are
pending, and, for this installation, which go-live steps are still open.

Phase status describes the software release. The checklist describes this server and network:
a phase can be built and still not be in use here (for example production BGP switched off).
"""
from __future__ import annotations

import json

import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import __version__
from . import telemetry as tm
from .changes import get_setting
from .models import BgpNeighbor, ProtectedPrefix, Router, RouterState

CURRENT = 8  # the phase this release completes

PHASES: list[dict] = [
    {"n": 1, "title": "Requirements and architecture",
     "scope": "Architecture, threat model, network design, safety rules.",
     "exit": "Design documents reviewed.", "release": "0.1"},
    {"n": 2, "title": "Data model, login and permissions",
     "scope": "Database and migrations, Argon2id passwords, JWT with refresh rotation, TOTP MFA, roles, tamper-evident audit log, configuration APIs.",
     "exit": "Migrations apply cleanly; every non-public route needs login.", "release": "0.2"},
    {"n": 3, "title": "Flow collection and live traffic",
     "scope": "NetFlow v9 / IPFIX / sFlow collector, SNMP counters, ClickHouse storage, live traffic dashboard.",
     "exit": "Replayed flows show correct per-destination pps/bps, tagged measured or estimated.", "release": "0.3"},
    {"n": 4, "title": "Detection and incidents",
     "scope": "Detection engine, traffic baselines, incident management.",
     "exit": "Lab UDP/SYN floods detected; a benign spike is not escalated.", "release": "0.4"},
    {"n": 5, "title": "MikroTik read-only integration",
     "scope": "RouterOS API over TLS with a read-only account: discovery, BGP state, routes, counters, flow export checks.",
     "exit": "Discovery, BGP state, routes and counters from a CCR2004.", "release": "0.5",
     "verify": ["Run against CCR2004/CCR2116 hardware (tested on the RouterOS protocol simulator)"]},
    {"n": 6, "title": "Blackhole controller (simulation)",
     "scope": "Dry-run plans, approvals, idempotency, expiry, policies, restart reconciliation; nothing leaves Shield.",
     "exit": "Full workflow works in simulation and survives restarts.", "release": "0.6"},
    {"n": 7, "title": "Staging BGP with FRR",
     "scope": "Shield's own FRR speaker to lab routers, generated router import filters, approval gates.",
     "exit": "The lab router accepts only authorised /32s; unauthorised and malformed requests are rejected.", "release": "0.7",
     "verify": ["Check the generated RouterOS import filter (set blackhole yes) on your RouterOS version"]},
    {"n": 8, "title": "Controlled live mitigation",
     "scope": "Production BGP sessions behind an MFA-protected switch, canary acceptance runs per peer, safety interlock, withdraw-all rollback.",
     "exit": "Acceptance tests prove unrelated prefixes are unaffected.", "release": "0.8"},
    {"n": 9, "title": "Selective steering, local filtering, scrubbing",
     "scope": "Selective upstream blackholing and steering, local filtering on the router, scrubbing-centre adapter.",
     "exit": "Each part: drops or diverts only the attack traffic, verified, reversible; nothing else on the router changes.",
     "release": "0.9", "in_progress": True,
     "parts": [
         {"title": "Local filtering on MikroTik (firewall raw drop rules)", "status": "done", "release": "0.9"},
         {"title": "Selective ISP steering (withhold / prepend towards one upstream)", "status": "pending"},
         {"title": "Scrubbing-centre adapter", "status": "pending"},
     ],
     "verify": ["Run local filtering against a real CCR2004/CCR2116 (tested on the RouterOS protocol simulator)"],
     "blocked": "Designed from the parts of the specification available; its Phase 9 text is incomplete."},
    {"n": 10, "title": "Alerting, reporting and hardening",
     "scope": "Email, Telegram and webhook alerts, reports, hardening, production checklist.",
     "exit": "To be defined with the rest of the specification.", "release": None},
]


def _status(p: dict) -> str:
    n = p["n"]
    if n <= CURRENT:
        return "done"
    if p.get("in_progress"):
        return "in_progress"
    return "next" if n == CURRENT + 1 else "pending"


def _peers(rds) -> dict[str, str]:
    if rds is None:
        return {}
    try:
        st = json.loads(rds.get("shield:mitigator:status") or "null") or {}
    except (redis.RedisError, ValueError):
        return {}
    peers = st.get("peers")
    return {p["address"]: p.get("state") for p in peers} if isinstance(peers, list) else {}


def checklist(db: Session) -> list[dict]:
    """Go-live steps for this installation, in order, each done / open with a hint."""
    try:
        rds = tm.rds()
    except Exception:
        rds = None
    items = []

    def add(key, title, done, hint, link, phase):
        items.append({"key": key, "title": title, "done": bool(done), "hint": None if done else hint, "link": link, "phase": phase})

    prefixes = db.scalar(select(func.count()).select_from(ProtectedPrefix).where(ProtectedPrefix.enabled.is_(True))) or 0
    add("prefixes", "Protected prefixes added", prefixes,
        "Add the address ranges Shield protects.", "/prefixes", 2)

    try:
        cs = tm.collector_status()
    except Exception:
        cs = {}
    receiving = cs.get("running") and any(not e.get("stale") for e in cs.get("exporters", []))
    add("flows", "Flow data arriving from the routers", receiving,
        "Export NetFlow/IPFIX on the upstream interfaces to this server (port 2055/4739).", "/health", 3)

    from . import asn
    add("asn", "IP-to-ASN table installed (names attack sources)", asn.status().get("loaded"),
        "Run: sudo systemctl start shield-asn-update (needs internet access to iptoasn.com).", "/history", 3)

    polled = db.scalar(select(func.count()).select_from(RouterState).join(Router, Router.id == RouterState.router_id)
                       .where(Router.enabled.is_(True), RouterState.ok.is_(True))) or 0
    add("router", "MikroTik router connected (read-only)", polled,
        "Add the router with its read-only API account and pin its certificate.", "/routers", 5)

    speaker = get_setting(db, "bgp_speaker", "simulated")
    add("speaker", "BGP speaker set to FRR", speaker == "frr",
        "Settings → bgp_speaker = frr (until then nothing leaves Shield).", "/settings", 7)

    neigh = db.execute(select(BgpNeighbor).where(BgpNeighbor.enabled.is_(True), BgpNeighbor.managed_by_shield.is_(True))).scalars().all()
    peers = _peers(rds)
    staging = [n for n in neigh if n.environment == "staging"]
    add("staging", "Staging session established", any(peers.get(str(n.neighbor_address)) == "Established" for n in staging),
        "Add a staging session to a lab router and install the generated filter.", "/bgp", 7)

    prod_on = bool(get_setting(db, "bgp_production_enabled", False))
    production = [n for n in neigh if n.environment == "production"]
    add("prod_session", "Production session recorded", production,
        "Add the session to your edge router with environment production.", "/bgp", 8)
    add("prod_switch", "Production announcements switched on", prod_on,
        "Settings → Production BGP (administrator with MFA).", "/settings", 8)
    add("acceptance", "Acceptance run passed on every production session",
        production and all(n.acceptance_passed_at for n in production),
        "BGP sessions → Acceptance run, with an unused address in a protected prefix.", "/bgp", 8)
    fr = db.execute(select(Router).where(Router.enabled.is_(True), Router.filter_password_enc.is_not(None))).first()
    add("filter", "Local filtering on the router (optional)",
        fr is not None and get_setting(db, "filter_backend", "simulated") == "routeros",
        "Add a filter account to the router (Routers & upstreams → Edit), test it, then set filter_backend = routeros.",
        "/routers", 9)
    return items


def roadmap(db: Session) -> dict:
    phases = [{**p, "status": _status(p), "verify": p.get("verify", []), "blocked": p.get("blocked"),
               "parts": p.get("parts", [])} for p in PHASES]
    return {"version": __version__, "current": CURRENT, "total": len(PHASES), "phases": phases,
            "checklist": checklist(db)}
