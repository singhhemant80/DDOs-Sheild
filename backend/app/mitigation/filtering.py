"""Local filtering (Phase 9): drop only the attack traffic on your own edge router.

Instead of blackholing a whole address, Shield adds narrow drop rules to the router's firewall
*raw* table (before connection tracking, the cheapest place to drop), for example "UDP from
port 123 to 163.5.191.20". Everything else to that address keeps flowing.

Where rules go is the `filter_backend` setting:
  simulated - rules are kept in Redis; nothing changes on any router (the default)
  routeros  - Shield's filter account adds them to /ip(v6)/firewall/raw on the router

On the router, Shield owns one chain, "shield-filter", entered by a single jump rule at the top
of the raw prerouting chain (comment "shield:jump"). Every rule Shield adds carries the comment
"shield:<action id>:<n>". Shield never edits or removes a rule without such a comment, and the
RouterOS client refuses any other change (mikrotik/filterapi.py).

What filtering cannot do: it runs on the router, after the traffic crossed the upstream link. If
the link itself is full, dropping on the router does not help; the planner says so.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Callable

import redis

from .speaker import SpeakerError, SpeakerRefused

KEY_SIM = "shield:sim:filters"
KEY_FAULT = "shield:sim:fault"

# Reflection services, by source port (same list as the detector).
REFLECTION_PORTS = {
    "dns_amplification": (53, "DNS"), "ntp_amplification": (123, "NTP"), "ssdp_amplification": (1900, "SSDP"),
    "cldap_amplification": (389, "CLDAP"), "memcached_amplification": (11211, "memcached"),
    "chargen_amplification": (19, "chargen"), "snmp_amplification": (161, "SNMP"), "wsd_amplification": (3702, "WS-Discovery"),
    "coap_amplification": (5683, "CoAP"), "ard_amplification": (3283, "ARD"), "portmap_amplification": (111, "portmap"),
    "netbios_amplification": (137, "NetBIOS"),
}
# Vectors that cannot be filtered without dropping the service itself.
NOT_FILTERABLE = {
    "syn_flood": "A SYN flood uses the same packets as real connections; dropping them drops every new connection. "
                 "Use SYN cookies on the server, or blackholing.",
    "ack_flood": "ACK packets are part of every TCP connection; dropping them breaks the service.",
    "rst_flood": "RST packets are part of normal TCP; dropping them is not a clean filter.",
    "volumetric_pps": "A high packet rate alone does not say what to drop.",
    "volumetric_bps": "High bandwidth alone does not say what to drop.",
    "traffic_anomaly": "Unusual traffic alone does not say what to drop.",
    "carpet_bombing": "Carpet bombing is spread over many addresses; filter by its type instead.",
}
PROTOCOLS = {"udp", "tcp", "icmp"}
MAX_RULES_PER_ACTION = 8


@dataclass(frozen=True)
class Match:
    """What one drop rule matches. dst is a single address or a prefix no broader than /24 (/48)."""
    dst: str
    protocol: str | None = None    # udp | tcp | icmp (icmpv6 on IPv6 is implied)
    src_port: int | None = None
    dst_port: int | None = None
    fragment: bool = False
    label: str = ""

    @property
    def family(self) -> int:
        return ipaddress.ip_network(self.dst).version

    def key(self) -> tuple:
        return (self.dst, self.protocol, self.src_port, self.dst_port, self.fragment)

    def describe(self) -> str:
        what = {"udp": "UDP", "tcp": "TCP", "icmp": "ICMP"}.get(self.protocol or "", "")
        parts = [f"{what} packets" if what else "packets"]
        if self.src_port:
            parts.append(f"from port {self.src_port}")
        if self.dst_port:
            parts.append(f"to port {self.dst_port}")
        if self.fragment:
            parts = ["fragmented " + parts[0]] + parts[1:]
        return f"{' '.join(parts)} to {self.dst}"

    def to_dict(self) -> dict:
        return {"dst": self.dst, "protocol": self.protocol, "src_port": self.src_port, "dst_port": self.dst_port,
                "fragment": self.fragment, "label": self.label}

    @classmethod
    def from_dict(cls, d: dict) -> "Match":
        return cls(dst=d["dst"], protocol=d.get("protocol"), src_port=d.get("src_port"), dst_port=d.get("dst_port"),
                   fragment=bool(d.get("fragment")), label=d.get("label") or "")


def validate(d: dict, target: str) -> Match:
    """Parse a requested match; raises ValueError with a message for the operator."""
    net = ipaddress.ip_network(target, strict=False)
    proto = (d.get("protocol") or None)
    if proto is not None:
        proto = str(proto).lower()
        if proto not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {', '.join(sorted(PROTOCOLS))}")
    ports = {}
    for k in ("src_port", "dst_port"):
        v = d.get(k)
        if v in (None, "", 0):
            ports[k] = None
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{k} must be a number") from None
        if not 1 <= v <= 65535:
            raise ValueError(f"{k} must be 1-65535")
        if proto not in ("udp", "tcp"):
            raise ValueError("ports need protocol udp or tcp")
        ports[k] = v
    frag = bool(d.get("fragment"))
    if proto is None and not frag:
        raise ValueError("a filter must name a protocol or fragments; dropping everything to an address is a blackhole")
    if proto == "tcp" and not ports["dst_port"] and not ports["src_port"]:
        raise ValueError("dropping all TCP to an address cuts every connection; give a port")
    label = str(d.get("label") or "")[:60]
    return Match(dst=str(net), protocol=proto, src_port=ports["src_port"], dst_port=ports["dst_port"], fragment=frag,
                 label=label)


def derive(vectors: list[str], target: str) -> tuple[list[Match], list[str]]:
    """Drop rules that match the attack's types, and the reasons for types that cannot be filtered."""
    out: list[Match] = []
    why: list[str] = []
    dst = str(ipaddress.ip_network(target, strict=False))
    for v in vectors or []:
        if v in REFLECTION_PORTS:
            port, name = REFLECTION_PORTS[v]
            out.append(Match(dst, "udp", src_port=port, label=f"{name} reflection"))
        elif v == "fragment_flood":
            out.append(Match(dst, None, fragment=True, label="fragments"))
        elif v == "icmp_flood":
            out.append(Match(dst, "icmp", label="ICMP flood"))
        elif v == "udp_flood":
            why.append("A UDP flood without a common source port cannot be filtered without dropping all UDP to the "
                       "address (DNS answers and games included). Add a rule with a destination port if the attack "
                       "targets one, or use blackholing.")
        elif v in NOT_FILTERABLE:
            why.append(NOT_FILTERABLE[v])
    seen, uniq = set(), []
    for m in out:
        if m.key() not in seen:
            seen.add(m.key())
            uniq.append(m)
    return uniq, why


def comment(action_id: str, n: int) -> str:
    return f"shield:{action_id}:{n}"


def to_attrs(m: Match, cmt: str) -> dict[str, str]:
    a = {"chain": "shield-filter", "action": "drop", "dst-address": m.dst}
    if m.protocol:
        a["protocol"] = "icmpv6" if (m.protocol == "icmp" and m.family == 6) else m.protocol
    if m.src_port:
        a["src-port"] = str(m.src_port)
    if m.dst_port:
        a["dst-port"] = str(m.dst_port)
    if m.fragment:
        a["fragment"] = "yes"
    a["comment"] = cmt
    return a


def same_rule(m: Match, row: dict) -> bool:
    """Does a rule read back from the router match exactly what Shield asked for?"""
    want = to_attrs(m, row.get("comment", ""))
    dst = row.get("dst-address", "")
    try:
        dst = str(ipaddress.ip_network(dst, strict=False))
    except ValueError:
        return False
    if dst != m.dst or row.get("chain") != "shield-filter" or row.get("action") != "drop":
        return False
    for k in ("protocol", "src-port", "dst-port"):
        if (row.get(k) or None) != want.get(k):
            return False
    if (row.get("fragment") in ("yes", "true")) != m.fragment:
        return False
    return row.get("disabled", "false") in ("false", "no")


# ---------------------------------------------------------------- backends
@dataclass(frozen=True)
class RouterTarget:
    id: int
    name: str
    host: str
    port: int
    use_tls: bool
    verify_tls: bool
    fingerprint: str | None
    username: str | None
    password_enc: str | None


class FilterBackend:
    name = "base"

    def rules(self, router: RouterTarget) -> dict[str, dict]:
        """Shield's rules on the router: comment -> {"id", "match" (row), "packets", "bytes"}."""
        raise NotImplementedError

    def add(self, router: RouterTarget, cmt: str, m: Match) -> str | None:
        raise NotImplementedError

    def remove(self, router: RouterTarget, cmt: str) -> None:
        raise NotImplementedError


class SimulatedFilters(FilterBackend):
    """Rules kept in Redis, so the whole workflow (verify, reconcile, counters) runs without a router.
    Fault injection: SET shield:sim:fault to "filter" (adds fail) or "filter-down"."""
    name = "simulated"

    def __init__(self, rds: redis.Redis):
        self.rds = rds

    def _fault(self, kind: str) -> bool:
        try:
            return self.rds.get(KEY_FAULT) in (kind, "filter-down")
        except redis.RedisError:
            return False

    def rules(self, router: RouterTarget) -> dict[str, dict]:
        if self._fault("filter-down"):
            raise SpeakerError(f"router {router.name} unreachable (simulated)")
        try:
            raw = self.rds.hgetall(KEY_SIM)
        except redis.RedisError as e:
            raise SpeakerError(f"simulated filter store unavailable: {e}") from None
        out = {}
        for k, v in raw.items():
            rid, _, cmt = k.partition("|")
            if rid == str(router.id):
                out[cmt] = json.loads(v)
        return out

    def add(self, router: RouterTarget, cmt: str, m: Match) -> str | None:
        if self._fault("filter"):
            raise SpeakerError("adding the rule failed (simulated fault)")
        row = {**to_attrs(m, cmt), "disabled": "false"}
        rid = f"*S{abs(hash(cmt)) % 0xFFFFFF:X}"
        self.rds.hset(KEY_SIM, f"{router.id}|{cmt}", json.dumps({"id": rid, "row": row, "packets": 0, "bytes": 0}))
        return rid

    def remove(self, router: RouterTarget, cmt: str) -> None:
        if self._fault("filter-down"):
            raise SpeakerError(f"router {router.name} unreachable (simulated)")
        self.rds.hdel(KEY_SIM, f"{router.id}|{cmt}")


class RouterOSFilters(FilterBackend):
    """Rules on the router itself, through the write-restricted FilterClient."""
    name = "routeros"

    def __init__(self, client_factory: Callable[[RouterTarget], object] | None = None):
        self.client_factory = client_factory or self._client

    @staticmethod
    def _client(r: RouterTarget):
        from .. import security
        from ..mikrotik.filterapi import FilterClient
        if not (r.username and r.password_enc):
            raise SpeakerRefused(f"router {r.name} has no filter account (Routers & upstreams → Edit → Filter account)")
        try:
            pw = security.decrypt_secret(r.password_enc)
        except Exception:
            raise SpeakerRefused(f"cannot decrypt the filter password of {r.name}; enter it again") from None
        return FilterClient(r.host, r.port, r.username, pw, use_tls=r.use_tls, verify_tls=r.verify_tls,
                            fingerprint=r.fingerprint)

    def _session(self, r: RouterTarget):
        from ..mikrotik.api import RouterOSError
        try:
            return self.client_factory(r).connect()
        except RouterOSError as e:
            raise SpeakerError(f"{r.name}: {e}") from None

    def rules(self, router: RouterTarget) -> dict[str, dict]:
        from ..mikrotik.api import RouterOSError
        c = self._session(router)
        try:
            out = {}
            for fam in (4, 6):
                try:
                    rows = c.shield_rules(fam)
                except RouterOSError as e:
                    if fam == 6 and "no such command" in str(e):
                        continue   # IPv6 package disabled
                    raise
                for r in rows:
                    if r.get("comment") == "shield:jump":
                        continue
                    out[r["comment"]] = {"id": r.get(".id"), "row": r, "packets": _int(r.get("packets")),
                                         "bytes": _int(r.get("bytes"))}
            return out
        except RouterOSError as e:
            raise SpeakerError(f"{router.name}: {e}") from None
        finally:
            c.close()

    def add(self, router: RouterTarget, cmt: str, m: Match) -> str | None:
        from ..mikrotik.api import RouterOSError, WriteRefused
        c = self._session(router)
        try:
            fam = m.family
            existing = c.shield_rules(fam)
            if not any(r.get("comment") == "shield:jump" for r in existing):
                first = c.first_rule_id(fam)
                jump = {"chain": "prerouting", "action": "jump", "jump-target": "shield-filter", "comment": "shield:jump"}
                if first:
                    jump["place-before"] = first
                c.add(fam, jump)
            for r in existing:   # replace a stale copy of the same rule
                if r.get("comment") == cmt:
                    c.remove(fam, r[".id"])
            return c.add(fam, to_attrs(m, cmt))
        except WriteRefused as e:
            raise SpeakerRefused(str(e)) from None
        except RouterOSError as e:
            raise SpeakerError(f"{router.name}: {e}") from None
        finally:
            c.close()

    def remove(self, router: RouterTarget, cmt: str) -> None:
        from ..mikrotik.api import RouterOSError
        c = self._session(router)
        try:
            for fam in (4, 6):
                try:
                    rows = c.shield_rules(fam)
                except RouterOSError:
                    if fam == 6:
                        continue
                    raise
                for r in rows:
                    if r.get("comment") == cmt:
                        c.remove(fam, r[".id"])
        except RouterOSError as e:
            raise SpeakerError(f"{router.name}: {e}") from None
        finally:
            c.close()


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def make_backend(name: str, rds: redis.Redis) -> FilterBackend:
    return RouterOSFilters() if name == "routeros" else SimulatedFilters(rds)


def target_of(r) -> RouterTarget:
    return RouterTarget(id=r.id, name=r.name, host=str(r.mgmt_address), port=r.api_port, use_tls=r.use_tls,
                        verify_tls=r.verify_tls, fingerprint=r.tls_fingerprint, username=r.filter_username,
                        password_enc=r.filter_password_enc)


# ---------------------------------------------------------------- planning
def _live_dst(net) -> dict | None:
    """The live per-second entry for the target (single address), with protocol and reflection rates."""
    from .. import telemetry as tm
    if net.num_addresses != 1:
        return None
    snap = tm.live_snapshot()
    if not snap.get("available"):
        return None
    ip = str(net.network_address)
    return next((d for d in snap.get("dsts", []) if d.get("ip") == ip), None)


def _estimate(m: Match, d: dict | None) -> float | None:
    if not d:
        return None
    if m.src_port and m.protocol == "udp":
        return float((d.get("reflect") or {}).get(str(m.src_port), 0.0))
    if m.fragment:
        return float(d.get("frag_pps") or 0.0)
    if m.protocol == "icmp" and not m.dst_port:
        return float(d.get("icmp_pps") or 0.0)
    return None


def _filter_plan(db, req, net, target: str, routes: list, checks: list, impact: list) -> None:
    """Routes for a local_filter plan: one entry per router, each with its drop rules."""
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from ..changes import get_setting
    from ..models import AttackIncident, FilterRule, Router, RouterState, UpstreamProvider

    def chk(level, code, msg):
        checks.append({"level": level, "code": code, "message": msg})

    # What to drop.
    matches: list[Match] = []
    if req.filters is not None:
        for i, f in enumerate(req.filters):
            try:
                matches.append(validate(f, target))
            except ValueError as e:
                chk("block", f"filter_{i}", f"Filter {i + 1}: {e}")
    else:
        vectors = []
        if req.incident_id:
            inc = db.get(AttackIncident, _uuid.UUID(req.incident_id))
            vectors = list(inc.vectors) if inc else []
        matches, why = derive(vectors, target)
        for w in why:
            chk("warn" if matches else "block", "not_filterable", w)
        if not matches and not why:
            chk("block", "no_filters", "No filter given, and no attack type that a filter could match. Choose what to drop.")
    if len({m.key() for m in matches}) != len(matches):
        chk("block", "filter_duplicate", "The same filter is listed twice.")
    if len(matches) > MAX_RULES_PER_ACTION:
        chk("block", "filter_count", f"At most {MAX_RULES_PER_ACTION} filters per action.")

    # Where.
    backend = get_setting(db, "filter_backend", "simulated")
    q = select(Router).where(Router.enabled).order_by(Router.name)
    all_routers = db.execute(q).scalars().all()
    chosen = [r for r in all_routers if req.router_ids is None or r.id in set(req.router_ids)]
    if req.router_ids is not None:
        for m in sorted(set(req.router_ids) - {r.id for r in chosen}):
            chk("block", "router_unknown", f"Router {m} does not exist or is disabled.")
    if not chosen:
        chk("block", "no_router", "No enabled router to put the filters on. Add your edge router under Routers & upstreams.")
    now = datetime.now(UTC)
    for r in chosen:
        st = db.get(RouterState, r.id)
        code = f"router_{r.id}"
        if backend == "routeros":
            if not (r.filter_username and r.filter_password_enc):
                chk("block", code, f"{r.name} has no filter account. Add one under Routers & upstreams → Edit "
                                   "(a separate RouterOS user that may write firewall rules).")
                continue
            if not r.use_tls:
                chk("block", code, f"{r.name}: changing a router needs the encrypted API (api-ssl).")
                continue
        if st is None or not st.ok or st.polled_at < now - timedelta(minutes=5):
            chk("warn", code, f"Shield has not read {r.name} successfully in the last 5 minutes; the filter may fail.")
        elif st.cpu_load is not None and st.cpu_load >= 80:
            chk("warn", code, f"{r.name} CPU is at {st.cpu_load}%. Dropping in the raw table is cheap, but a router this "
                              "busy may already be dropping packets.")
        else:
            chk("ok", code, f"{r.name} reachable" + (f", CPU {st.cpu_load}%" if st.cpu_load is not None else "") + ".")
        if st is not None and any(c.get("code") == "l3hw" for c in (st.checks or [])):
            chk("warn", f"{code}_l3hw", f"{r.name} routes some traffic in hardware (L3HW offload): firewall rules do not "
                                        "see those packets, so the filter may not drop all of the attack.")
        rules = [m.to_dict() for m in matches]
        desc = "; ".join(m.describe() for m in matches)
        routes.append({"peer": f"router:{r.id}", "upstream_id": None, "upstream": None, "asn": None, "prefix": target,
                       "router_id": r.id, "router": r.name, "filters": rules, "communities": [], "next_hop": None,
                       "no_export": False,
                       "description": f"on {r.name}: drop {desc}" if matches else f"on {r.name}: (no filters)"})

    # Limits.
    exclude = [str(x) for x in req.exclude_action_ids]
    q = select(func.count()).select_from(FilterRule).where(FilterRule.status.in_(("pending", "active", "removing")))
    if exclude:
        q = q.where(~FilterRule.action_id.in_(exclude))
    in_use = db.execute(q).scalar_one()
    cap = int(get_setting(db, "filter_max_rules", 50))
    need = len(matches) * len(routes)
    if in_use + need > cap:
        chk("block", "filter_limit", f"{in_use} filter rules are in use; this needs {need} more and the limit is {cap}.")

    # What it changes, and what it cannot do.
    d = _live_dst(net)
    total = float(d.get("pps") or 0) if d else None
    est = [_estimate(m, d) for m in matches]
    if backend != "routeros":
        chk("warn", "filter_simulated", "Filter backend is simulated: nothing changes on any router. Set filter_backend "
                                        "to routeros in Settings to filter for real.")
    else:
        chk("warn", "filter_real", "This adds firewall rules on your router (chain shield-filter, raw table).")
    if matches:
        names = ", ".join(r["router"] for r in routes) or "your routers"
        impact.append(f"{names} drop(s) only: " + "; ".join(m.describe() for m in matches) + f". All other traffic to "
                      f"{target} keeps flowing.")
        if total and all(e is not None for e in est):
            dropped = sum(est)
            impact.append(f"Right now that is about {dropped:,.0f} of {total:,.0f} packets/s to {target} "
                          f"({dropped / total:.0%}).")
    bps = float(d.get("bps") or 0) if d else 0.0
    if not bps and req.incident_id:
        inc = db.get(AttackIncident, _uuid.UUID(req.incident_id))
        bps = float(inc.peak_bps or 0) if inc else 0.0
    caps = [u.capacity_mbps for u in db.execute(select(UpstreamProvider).where(UpstreamProvider.enabled)).scalars()
            if u.capacity_mbps]
    if caps and bps:
        link = sum(caps) * 1e6
        if bps >= 0.8 * link:
            chk("block" if req.automatic else "warn", "link_saturated",
                f"The attack ({bps / 1e9:.1f} Gb/s) is close to or over your upstream capacity ({link / 1e9:.1f} Gb/s). "
                "Filtering on your router cannot help when the link itself is full: the provider has to drop it "
                "(upstream blackholing or scrubbing).")
    impact.append("Filtering runs on your router, after the traffic has crossed your upstream links: it protects the "
                  "server, not a full link.")
