"""Selective upstream steering (Phase 9 part 2): move inbound traffic for an attacked prefix
away from one upstream, without blackholing anything.

Inbound traffic follows what you announce. Shield changes what your edge router announces to one
upstream, for one exact prefix (normally the /24 holding the attacked address):

  withhold     stop announcing the prefix to that upstream; the internet reaches it over the others
  prepend N    make the path through that upstream N AS hops longer, so networks that can choose
               prefer the others (some traffic still arrives over it)
  communities  tag the announcement with the upstream's own action communities (for example its
               "do not announce to <peer>" or "prepend towards <region>"), from its documentation

On the router, each upstream gets a Shield chain "shield-steer-<upstream id>" in /routing/filter,
entered by one jump rule at the top of that upstream's BGP output chain (comment
"shield:steer-jump:<id>"). Shield's rules carry "shield:<action>:<n>" comments; nothing else is
edited or removed, and the RouterOS client refuses any other change (mikrotik/filterapi.py).

Safety: Shield never withholds a prefix from every upstream (it would become unreachable), and
warns when the remaining upstreams may not have the capacity for the traffic moved onto them.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

import redis

from .filtering import FilterBackend, RouterTarget, _int
from .speaker import SpeakerError, SpeakerRefused

KEY_SIM = "shield:sim:steer"
KEY_FAULT = "shield:sim:fault"
MODES = ("withhold", "prepend", "communities")


def covering(target: str) -> ipaddress._BaseNetwork:
    """The announced prefix a steering action acts on: the /24 (/48) holding the target, or the
    target itself if it is already that size or broader."""
    net = ipaddress.ip_network(target, strict=False)
    limit = 24 if net.version == 4 else 48
    return net.supernet(new_prefix=limit) if net.prefixlen > limit else net


@dataclass(frozen=True)
class Steer:
    prefix: str
    upstream_id: int
    mode: str
    prepend: int = 0
    communities: tuple[str, ...] = ()
    out_chain: str = ""          # the router's BGP output chain towards this upstream
    upstream: str = ""

    @property
    def chain(self) -> str:
        return f"shield-steer-{self.upstream_id}"

    def rule(self) -> str:
        if self.mode == "withhold":
            body = "reject;"
        elif self.mode == "prepend":
            body = f"set bgp-path-prepend {self.prepend};"
        else:
            body = f"append bgp-communities {','.join(self.communities)};"
        return f"if (dst == {self.prefix}) {{ {body} }}"

    def describe(self) -> str:
        who = self.upstream or f"upstream {self.upstream_id}"
        if self.mode == "withhold":
            return f"stop announcing {self.prefix} to {who}"
        if self.mode == "prepend":
            return f"prepend {self.prepend}x towards {who} for {self.prefix}"
        return f"tag {self.prefix} towards {who} with {', '.join(self.communities)}"

    def to_dict(self) -> dict:
        return {"prefix": self.prefix, "upstream_id": self.upstream_id, "mode": self.mode, "prepend": self.prepend,
                "communities": list(self.communities), "out_chain": self.out_chain, "upstream": self.upstream}

    @classmethod
    def from_dict(cls, d: dict) -> "Steer":
        return cls(prefix=d["prefix"], upstream_id=int(d["upstream_id"]), mode=d["mode"], prepend=int(d.get("prepend") or 0),
                   communities=tuple(d.get("communities") or ()), out_chain=d.get("out_chain") or "",
                   upstream=d.get("upstream") or "")


def same_rule(s: Steer, row: dict) -> bool:
    return row.get("chain") == s.chain and row.get("rule", "").strip() == s.rule() and \
        row.get("disabled", "false") in ("false", "no")


# ---------------------------------------------------------------- backends
class SimulatedSteering(FilterBackend):
    """Steering rules kept in Redis; no router changes. Fault: SET shield:sim:fault "steer"."""
    name = "simulated"

    def __init__(self, rds: redis.Redis):
        self.rds = rds

    def _fault(self) -> bool:
        try:
            return self.rds.get(KEY_FAULT) == "steer"
        except redis.RedisError:
            return False

    def rules(self, router: RouterTarget) -> dict[str, dict]:
        try:
            raw = self.rds.hgetall(KEY_SIM)
        except redis.RedisError as e:
            raise SpeakerError(f"simulated steering store unavailable: {e}") from None
        out = {}
        for k, v in raw.items():
            rid, _, cmt = k.partition("|")
            if rid == str(router.id):
                out[cmt] = json.loads(v)
        return out

    def add(self, router: RouterTarget, cmt: str, s: Steer) -> str | None:
        if self._fault():
            raise SpeakerError("adding the steering rule failed (simulated fault)")
        row = {"chain": s.chain, "rule": s.rule(), "comment": cmt, "disabled": "false"}
        rid = f"*T{abs(hash(cmt)) % 0xFFFFFF:X}"
        self.rds.hset(KEY_SIM, f"{router.id}|{cmt}", json.dumps({"id": rid, "row": row}))
        return rid

    def remove(self, router: RouterTarget, cmt: str) -> None:
        self.rds.hdel(KEY_SIM, f"{router.id}|{cmt}")


class RouterOSSteering(FilterBackend):
    """Steering rules in the router's /routing/filter, through the write-restricted FilterClient."""
    name = "routeros"

    def __init__(self, client_factory=None):
        from .filtering import RouterOSFilters
        self._f = RouterOSFilters(client_factory)

    def _session(self, r: RouterTarget):
        return self._f._session(r)

    def rules(self, router: RouterTarget) -> dict[str, dict]:
        from ..mikrotik.api import RouterOSError
        c = self._session(router)
        try:
            return {r["comment"]: {"id": r.get(".id"), "row": r} for r in c.steer_rules()
                    if not r["comment"].startswith("shield:steer-jump:")}
        except RouterOSError as e:
            raise SpeakerError(f"{router.name}: {e}") from None
        finally:
            c.close()

    def add(self, router: RouterTarget, cmt: str, s: Steer) -> str | None:
        from ..mikrotik.api import RouterOSError, WriteRefused
        if not s.out_chain:
            raise SpeakerRefused(f"no BGP output chain known for {s.upstream or s.upstream_id} on {router.name}")
        c = self._session(router)
        try:
            existing = c.steer_rules()
            for r in existing:      # replace a stale copy of the same rule
                if r.get("comment") == cmt:
                    c.remove_steer(r[".id"])
            rid = c.add_steer({"chain": s.chain, "rule": s.rule(), "comment": cmt})
            jump = f"shield:steer-jump:{s.upstream_id}"
            if not any(r.get("comment") == jump for r in existing):
                first = c.first_rule_in(s.out_chain)
                if first is None:
                    # An output chain with no rules of its own would end after our jump: refuse rather
                    # than risk changing what the router announces.
                    c.remove_steer(rid)
                    raise SpeakerRefused(f"the output chain {s.out_chain} on {router.name} has no rules; "
                                         "Shield adds its jump only in front of an existing filter")
                c.add_steer({"chain": s.out_chain, "rule": f"jump {s.chain}", "comment": jump, "place-before": first})
            return rid
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
            rows = c.steer_rules()
            mine = [r for r in rows if r.get("comment") == cmt]
            for r in mine:
                chain = r.get("chain", "")
                left = [x for x in rows if x.get("chain") == chain and x.get("comment") != cmt]
                if not left:      # last rule in this upstream's chain: take the jump out first
                    uid = chain.rpartition("-")[2]
                    for j in rows:
                        if j.get("comment") == f"shield:steer-jump:{uid}":
                            c.remove_steer(j[".id"])
                c.remove_steer(r[".id"])
        except RouterOSError as e:
            raise SpeakerError(f"{router.name}: {e}") from None
        finally:
            c.close()


def make_backend(name: str, rds: redis.Redis) -> FilterBackend:
    return RouterOSSteering() if name == "routeros" else SimulatedSteering(rds)


# ---------------------------------------------------------------- planning
def _steer_plan(db, req, net, target: str, routes: list, checks: list, impact: list) -> None:
    from sqlalchemy import cast, func, select
    from sqlalchemy.dialects.postgresql import CIDR

    from .. import netvalidate as nv
    from .. import telemetry as tm
    from ..changes import get_setting
    from ..models import ActionState, CustomerIpAssignment, FilterRule, MitigationAction, Router, RouterState, Strategy, UpstreamProvider

    def chk(level, code, msg):
        checks.append({"level": level, "code": code, "message": msg})

    backend = get_setting(db, "steering_backend", "simulated")
    ups = db.execute(select(UpstreamProvider).where(UpstreamProvider.enabled).order_by(UpstreamProvider.name)).scalars().all()
    carrying = [u for u in ups if u.router_id]          # upstreams your routers announce to
    by_id = {u.id: u for u in ups}
    if len(carrying) < 2:
        chk("block", "steer_upstreams", "Steering needs at least two upstreams linked to your routers (Routers & upstreams → "
                                        "Edit upstream → Edge router); with one there is nowhere to move the traffic.")

    # What to do, per upstream.
    entries = req.steering
    if entries is None:
        protected = [u for u in carrying if u.ddos_protected]
        if protected and len(protected) < len(carrying):
            entries = [{"upstream_id": u.id, "mode": "withhold"} for u in carrying if not u.ddos_protected]
            chk("ok", "steer_default", f"Suggested: move {target} onto the DDoS-protected upstream(s) "
                                       f"{', '.join(u.name for u in protected)} by withholding it from the others.")
        else:
            entries = []
            chk("block", "steer_choose", "Choose which upstream to move the traffic away from, and how.")

    specs: list[Steer] = []
    seen: set[int] = set()
    for i, e in enumerate(entries):
        code = f"steer_{i}"
        try:
            uid = int(e.get("upstream_id"))
        except (TypeError, ValueError):
            chk("block", code, f"Entry {i + 1}: choose an upstream.")
            continue
        u = by_id.get(uid)
        if u is None:
            chk("block", code, f"Upstream {uid} does not exist or is disabled.")
            continue
        if uid in seen:
            chk("block", code, f"{u.name} is listed twice.")
            continue
        seen.add(uid)
        mode = e.get("mode")
        if mode not in MODES:
            chk("block", code, f"{u.name}: mode must be withhold, prepend or communities.")
            continue
        prepend, comms = 0, ()
        if mode == "prepend":
            try:
                prepend = int(e.get("prepend") or 3)
            except (TypeError, ValueError):
                prepend = 0
            if not 1 <= prepend <= 5:
                chk("block", code, f"{u.name}: prepend 1 to 5 times.")
                continue
        if mode == "communities":
            raw = e.get("communities") or []
            try:
                comms = tuple(nv.normalise_community(c) for c in raw)
            except ValueError as err:
                chk("block", code, f"{u.name}: {err}")
                continue
            if not 1 <= len(comms) <= 4:
                chk("block", code, f"{u.name}: give 1 to 4 of the provider's action communities.")
                continue
        if not u.router_id:
            chk("block", code, f"{u.name} is not linked to one of your routers, so Shield does not know where its session is.")
            continue
        r = db.get(Router, u.router_id)
        st = db.get(RouterState, u.router_id)
        if r is None or not r.enabled:
            chk("block", code, f"{u.name}: its router is missing or disabled.")
            continue
        if backend == "routeros" and not (r.filter_username and r.filter_password_enc):
            chk("block", code, f"{r.name} has no filter account (Routers & upstreams → Edit), which steering uses to change "
                               "its BGP output filter.")
            continue
        sess = [b for b in (st.bgp if st else []) or [] if str(b.get("remote_as")) == str(u.asn) and not b.get("disabled")]
        if not sess:
            chk("block", code, f"Shield cannot find {r.name}'s BGP session to {u.name} (AS{u.asn}) in the router's "
                               "configuration. Check that Shield reads the router.")
            continue
        chains = sorted({b.get("output_filter") for b in sess if b.get("output_filter")})
        if not chains:
            chk("block", code, f"{r.name}'s session to {u.name} has no output filter chain. Steering adds its rules in "
                               "front of that filter; set one up first (most setups have one to limit what is announced).")
            continue
        if len(chains) > 1:
            chk("warn", code, f"{r.name} has several sessions to {u.name} with different output chains; Shield uses {chains[0]}.")
        exact = any(x.get("dst") == target for x in ((st.routes or {}).get("items") or []))
        if not exact:
            chk("warn", f"{code}_announced", f"Shield cannot see a route for exactly {target} on {r.name}. Steering only "
                                             f"changes an announcement of exactly {target}; if you announce a larger "
                                             "aggregate only, nothing changes.")
        s = Steer(prefix=target, upstream_id=u.id, mode=mode, prepend=prepend, communities=comms, out_chain=chains[0],
                  upstream=u.name)
        specs.append(s)
        routes.append({"peer": f"steer:{u.id}", "upstream_id": u.id, "upstream": u.name, "asn": u.asn, "prefix": target,
                       "router_id": r.id, "router": r.name, "steering": [s.to_dict()], "communities": [], "next_hop": None,
                       "no_export": False, "description": f"on {r.name}: {s.describe()}"})
        if mode == "communities":
            chk("warn", f"{code}_comm", f"Check {', '.join(comms)} against {u.name}'s documentation: Shield cannot verify "
                                        "what a provider's action communities do.")

    # Never leave the prefix unannounced.
    exclude = [str(x) for x in req.exclude_action_ids]
    q = select(MitigationAction).where(MitigationAction.strategy == Strategy.STEERING,
                                       MitigationAction.state.in_([ActionState.APPROVED, ActionState.EXECUTING,
                                                                   ActionState.ACTIVE, ActionState.PROPOSED]),
                                       cast(target, CIDR) == MitigationAction.target)
    if exclude:
        q = q.where(~MitigationAction.id.in_(exclude))
    others = db.execute(q).scalars().all()
    for a in others:
        if any(s.upstream_id == a.upstream_id for s in specs):
            chk("block", "duplicate", f"{target} is already being steered at {by_id.get(a.upstream_id).name if by_id.get(a.upstream_id) else a.upstream_id} "
                                      f"({str(a.id)[:8]}). Withdraw it first to change it.")
    withheld = {s.upstream_id for s in specs if s.mode == "withhold"} | {
        a.upstream_id for a in others
        if (((a.plan or {}).get("route") or {}).get("steering") or [{}])[0].get("mode") == "withhold"}
    remaining = [u for u in carrying if u.id not in withheld]
    if carrying and not remaining:
        chk("block", "steer_unreachable", f"This would stop announcing {target} to every upstream: it would become "
                                          "unreachable. Keep at least one upstream (blackholing is the tool for that).")
    elif withheld and remaining:
        live = tm.live_snapshot()
        bps = 0.0
        for d in (live.get("dsts") or []) if live.get("available") else []:
            try:
                if ipaddress.ip_address(d["ip"]) in net:
                    bps += float(d.get("bps") or 0)
            except (ValueError, KeyError):
                continue
        cap = sum(u.capacity_mbps or 0 for u in remaining) * 1e6
        names = ", ".join(u.name for u in remaining)
        impact.append(f"Traffic from the internet to {target} will arrive only over {names}, once BGP has converged "
                      "(usually seconds to a few minutes).")
        if cap and bps >= 0.8 * cap:
            chk("warn", "steer_capacity", f"Traffic to {target} now is {bps / 1e9:.1f} Gb/s, close to or over the capacity left "
                                          f"on {names} ({cap / 1e9:.1f} Gb/s). Those links may fill up.")
        elif not cap:
            chk("warn", "steer_capacity", f"Set the link capacity of {names} so Shield can check they can take the traffic.")
    for s in specs:
        if s.mode == "prepend":
            impact.append(f"The path to {target} through {s.upstream} becomes {s.prepend} AS hops longer: most networks will "
                          "prefer your other upstreams, but some traffic still arrives through it.")
        if s.mode == "communities":
            impact.append(f"{s.upstream} receives {target} tagged {', '.join(s.communities)}; what that does is up to "
                          f"{s.upstream}'s policy.")
    n_addr = net.num_addresses
    custs = db.execute(select(func.count()).select_from(CustomerIpAssignment).where(
        CustomerIpAssignment.address.op("<<=")(cast(target, CIDR)))).scalar_one()
    impact.append(f"Steering moves the whole of {target} ({n_addr} addresses{f', {custs} customer assignments' if custs else ''}), "
                  "not just the attacked address. Nothing is dropped: all traffic still reaches it.")

    # Limits.
    q = select(func.count()).select_from(FilterRule).where(FilterRule.kind == "steer",
                                                          FilterRule.status.in_(("pending", "active", "removing")))
    if exclude:
        q = q.where(~FilterRule.action_id.in_(exclude))
    in_use = db.execute(q).scalar_one()
    cap_rules = int(get_setting(db, "steering_max_rules", 20))
    if in_use + len(specs) > cap_rules:
        chk("block", "steer_limit", f"{in_use} steering rules are in use; this needs {len(specs)} more and the limit is {cap_rules}.")
    if backend != "routeros":
        chk("warn", "steer_simulated", "Steering backend is simulated: nothing changes on any router. Set steering_backend "
                                       "to routeros in Settings to steer for real.")
    else:
        chk("warn", "steer_real", "This changes what your router announces to an upstream (its BGP output filter).")
