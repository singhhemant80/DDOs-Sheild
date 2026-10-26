"""FRR speaker (staging peers; production peers when switched on and accepted).

Shield runs its own FRR (bgpd) on the Shield server and owns that BGP configuration. The controller
talks to it through `vtysh`; every value placed in a command is re-serialised from a parsed IP
network, BGP community or integer and the finished line is checked against a strict character set,
because vtysh executes a newline inside one `-c` argument as a second command.

Configuration Shield maintains (nothing else in FRR is touched):

    router bgp <local AS>              no bgp default ipv4-unicast, no bgp network import-check
     neighbor <peer> ...               remote-as, port, ebgp-multihop, update-source, password
     address-family ipv4|ipv6 unicast
      network <blackholed prefix>      one per announced prefix
      neighbor <peer> route-map SHIELD-DENY in        Shield never accepts a route
      neighbor <peer> route-map SHIELD-OUT-<tag> out  only prefixes in that peer's list leave
      neighbor <peer> maximum-prefix-out <n>          hard cap per session
    ip prefix-list SHIELD4-<tag> / ipv6 prefix-list SHIELD6-<tag>   the peer's announcements
    route-map SHIELD-OUT-<tag>         match the list; set community, no-export, discard next hop;
                                       deny everything else

Each announcement is checked again here before it is configured, independently of the planner:
the action must exist and be executing or active, the prefix must be inside an enabled, verified
protected prefix that allows blackholing and no broader than it permits, the peer must be a
Shield-managed staging session, and the attributes must match the peer's current policy.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Callable

import redis
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import netvalidate as nv
from .. import security
from ..changes import get_setting
from ..models import (
    ActionState, BgpNeighbor, BgpPurpose, CustomerIpAssignment, MitigationAction, ProtectedPrefix, UpstreamProvider,
)
from .speaker import Route, SpeakerError, SpeakerRefused

log = logging.getLogger("shield.frr")

KEY_OWNERS = "shield:frr:owners"
SAFE_LINE = re.compile(r"^[A-Za-z0-9 .:/_-]{1,200}$")
SAFE_PASSWORD = re.compile(r"^[A-Za-z0-9._-]{8,80}$")
# Production sessions are configured only while the bgp_production_enabled switch is on (Phase 8),
# and carry real blackholes only after their acceptance run passed.


@dataclass
class Neighbor:
    address: str
    remote_asn: int
    local_asn: int
    port: int = 179
    multihop: int | None = None
    update_source: str | None = None
    max_prefix_out: int | None = None
    password: str | None = None
    environment: str = "staging"
    name: str = ""
    accepted: bool = True       # staging sessions need no acceptance run

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version


@dataclass
class PeerSpec:
    key: str                              # "upstream:<id>" or "internal"
    tag: str                              # used in FRR object names
    label: str
    communities: tuple[str, ...]
    no_export: bool
    planned_next_hop: str | None          # what the plan carries (None = discard default)
    next_hop_v4: str
    next_hop_v6: str
    neighbors: list[Neighbor] = field(default_factory=list)

    @property
    def unaccepted(self) -> list[str]:
        return [nb.name for nb in self.neighbors if not nb.accepted]


def _check_line(line: str) -> str:
    if not SAFE_LINE.match(line):
        raise SpeakerRefused(f"refusing to send an unsafe command to FRR: {line!r}")
    return line


def _net(prefix: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(prefix, strict=True)
    except (ValueError, TypeError) as e:
        raise SpeakerRefused(f"malformed prefix {prefix!r}: {e}") from None


class FrrSpeaker:
    name = "frr"

    def __init__(self, sessions: Callable[[], Session], rds: redis.Redis, vtysh: str = "vtysh",
                 pathspace: str | None = None, timeout: float = 10.0):
        self.sessions = sessions
        self.rds = rds
        self.vtysh = vtysh
        self.pathspace = pathspace
        self.timeout = timeout
        self._applied_hash: str | None = None

    # ------------------------------------------------------------ vtysh
    def _vtysh(self, lines: list[str], *, configure: bool) -> str:
        argv = [self.vtysh] + (["-N", self.pathspace] if self.pathspace else [])
        if configure:
            argv += ["-c", "configure terminal"]
        for line in lines:
            argv += ["-c", _check_line(line)]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError:
            raise SpeakerError("vtysh not found: is FRR installed?") from None
        except subprocess.TimeoutExpired:
            raise SpeakerError("FRR did not answer within 10 s") from None
        out = "\n".join(x for x in (p.stdout + "\n" + p.stderr).splitlines() if "vtysh.conf" not in x)
        errors = [x for x in out.splitlines() if x.startswith("%") or "Exiting: failed to connect" in x]
        if p.returncode != 0 or errors:
            raise SpeakerError("FRR: " + ("; ".join(errors) or out.strip() or f"vtysh exit {p.returncode}")[:300])
        return p.stdout

    def _show_json(self, cmd: str) -> dict:
        out = self._vtysh([cmd], configure=False)
        try:
            return json.loads(out or "{}")
        except ValueError:
            raise SpeakerError(f"FRR returned unreadable output for {cmd!r}") from None

    # ------------------------------------------------------------ desired peers (from the database)
    def peers(self, db: Session) -> dict[str, PeerSpec]:
        out: dict[str, PeerSpec] = {}
        nh4 = str(ipaddress.IPv4Address(get_setting(db, "rtbh_discard_nexthop_v4", "192.0.2.1")))
        nh6 = str(ipaddress.IPv6Address(get_setting(db, "rtbh_discard_nexthop_v6", "100::1")))
        rows = db.execute(select(BgpNeighbor).where(
            BgpNeighbor.router_id.is_(None), BgpNeighbor.managed_by_shield, BgpNeighbor.enabled,
            BgpNeighbor.purpose.in_([BgpPurpose.RTBH_UPSTREAM, BgpPurpose.RTBH_SIGNAL]))
            .order_by(BgpNeighbor.id)).scalars().all()
        production = bool(get_setting(db, "bgp_production_enabled", False))
        for n in rows:
            if n.environment != "staging" and not production:
                continue
            if n.purpose == BgpPurpose.RTBH_UPSTREAM:
                if n.upstream_id is None:
                    continue
                up = db.get(UpstreamProvider, n.upstream_id)
                pol = up.rtbh_policy if up else None
                if not (up and up.enabled and pol and pol.enabled and pol.verified_at):
                    continue
                key = f"upstream:{up.id}"
                spec = out.get(key) or PeerSpec(
                    key=key, tag=f"u{up.id}", label=up.name,
                    communities=tuple(nv.normalise_community(c) for c in pol.communities), no_export=pol.add_no_export,
                    planned_next_hop=str(pol.next_hop) if pol.next_hop else None,
                    next_hop_v4=str(pol.next_hop) if pol.next_hop and ipaddress.ip_address(str(pol.next_hop)).version == 4 else nh4,
                    next_hop_v6=str(pol.next_hop) if pol.next_hop and ipaddress.ip_address(str(pol.next_hop)).version == 6 else nh6)
            else:
                comm = get_setting(db, "internal_blackhole_community", "")
                if not comm:
                    continue
                key = "internal"
                spec = out.get(key) or PeerSpec(key=key, tag="int", label="own edge routers",
                                                communities=(nv.normalise_community(comm),), no_export=True,
                                                planned_next_hop=None, next_hop_v4=nh4, next_hop_v6=nh6)
            pw = None
            if n.md5_password_enc:
                pw = security.decrypt_secret(n.md5_password_enc)
                if not SAFE_PASSWORD.match(pw):
                    raise SpeakerRefused(f"BGP password for {n.name} has unsupported characters")
            spec.neighbors.append(Neighbor(
                address=str(ipaddress.ip_address(str(n.neighbor_address))), remote_asn=int(n.remote_asn),
                local_asn=int(n.local_asn), port=int(n.remote_port or 179), multihop=n.ebgp_multihop,
                update_source=str(ipaddress.ip_address(str(n.local_address))) if n.local_address else None,
                max_prefix_out=n.max_prefix_out, password=pw, environment=n.environment, name=n.name,
                accepted=n.environment == "staging" or n.acceptance_passed_at is not None))
            out[key] = spec
        return out

    # ------------------------------------------------------------ base configuration
    def _render(self, db: Session, peers: dict[str, PeerSpec]) -> tuple[int, list[str]]:
        asns = {nb.local_asn for p in peers.values() for nb in p.neighbors}
        if len(asns) > 1:
            raise SpeakerRefused(f"Shield's BGP sessions use different local AS numbers ({sorted(asns)}); use one")
        rid = get_setting(db, "bgp_router_id", "")
        if not asns:
            return 0, []
        asn = asns.pop()
        lines = ["route-map SHIELD-DENY deny 10", "exit"]
        for p in peers.values():
            comms = " ".join(list(p.communities) + (["no-export"] if p.no_export else []))
            # A first entry that can never match an announcement, so the lists exist while empty.
            # (A trailing "deny any" would sort before FRR's auto-numbered entries and block them;
            # anything not listed is denied anyway.)
            lines += [f"ip prefix-list SHIELD4-{p.tag} seq 1 deny 0.0.0.0/32",
                      f"ipv6 prefix-list SHIELD6-{p.tag} seq 1 deny ::/128"]
            for seq, fam in ((10, 4), (20, 6)):
                lines.append(f"route-map SHIELD-OUT-{p.tag} permit {seq}")
                lines.append(f"match {'ip' if fam == 4 else 'ipv6'} address prefix-list SHIELD{fam}-{p.tag}")
                lines.append(f"set community {comms}" if comms else "no set community")
                lines.append(f"set ip next-hop {p.next_hop_v4}" if fam == 4 else f"set ipv6 next-hop global {p.next_hop_v6}")
                lines.append("exit")
            lines += [f"route-map SHIELD-OUT-{p.tag} deny 100", "exit"]
            # Production sessions not yet accepted get only the acceptance canary.
            lines += [f"ip prefix-list SHIELD4-ACC-{p.tag} seq 1 deny 0.0.0.0/32",
                      f"ipv6 prefix-list SHIELD6-ACC-{p.tag} seq 1 deny ::/128"]
            for seq, fam in ((10, 4), (20, 6)):
                lines.append(f"route-map SHIELD-ACC-{p.tag} permit {seq}")
                lines.append(f"match {'ip' if fam == 4 else 'ipv6'} address prefix-list SHIELD{fam}-ACC-{p.tag}")
                lines.append(f"set community {comms}" if comms else "no set community")
                lines.append(f"set ip next-hop {p.next_hop_v4}" if fam == 4 else f"set ipv6 next-hop global {p.next_hop_v6}")
                lines.append("exit")
            lines += [f"route-map SHIELD-ACC-{p.tag} deny 100", "exit"]
        lines.append(f"router bgp {asn}")
        if rid:
            lines.append(f"bgp router-id {ipaddress.IPv4Address(rid)}")
        lines += ["no bgp default ipv4-unicast", "no bgp network import-check"]
        for p in peers.values():
            for nb in p.neighbors:
                lines.append(f"neighbor {nb.address} remote-as {nb.remote_asn}")
                lines.append(f"neighbor {nb.address} description shield-{p.tag}")
                lines.append(f"neighbor {nb.address} timers connect 10")
                if nb.port != 179:
                    lines.append(f"neighbor {nb.address} port {int(nb.port)}")
                if nb.multihop and nb.remote_asn != asn:
                    lines.append(f"neighbor {nb.address} ebgp-multihop {int(nb.multihop)}")
                if nb.update_source:
                    lines.append(f"neighbor {nb.address} update-source {nb.update_source}")
                if nb.password:
                    lines.append(f"neighbor {nb.address} password {nb.password}")
        for fam in (4, 6):
            lines.append(f"address-family {'ipv4' if fam == 4 else 'ipv6'} unicast")
            for p in peers.values():
                for nb in p.neighbors:
                    if nb.version != fam:
                        continue
                    out_map = f"SHIELD-OUT-{p.tag}" if nb.accepted else f"SHIELD-ACC-{p.tag}"
                    lines += [f"neighbor {nb.address} activate",
                              f"neighbor {nb.address} route-map SHIELD-DENY in",
                              f"neighbor {nb.address} route-map {out_map} out"]
                    if nb.max_prefix_out:
                        lines.append(f"neighbor {nb.address} maximum-prefix-out {int(nb.max_prefix_out)}")
            lines.append("exit-address-family")
        lines.append("exit")
        return asn, lines

    def _running(self) -> str:
        return self._vtysh(["show running-config"], configure=False)

    def sync(self, db: Session | None = None) -> dict:
        """Bring FRR's sessions and policies in line with the database. Cheap when nothing changed."""
        own = db is None
        db = db or self.sessions()
        try:
            peers = self.peers(db)
            asn, lines = self._render(db, peers)
        finally:
            if own:
                db.close()
        running = self._running()
        digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
        if digest == self._applied_hash and "route-map SHIELD-DENY" in running:
            return {"changed": False, "peers": len(peers)}
        # Remove sessions Shield configured earlier that are no longer wanted.
        stale = []
        m = re.search(r"^router bgp (\d+)", running, re.M)
        if m:
            wanted = {nb.address for p in peers.values() for nb in p.neighbors}
            for addr in re.findall(r"^ neighbor (\S+) description shield-", running, re.M):
                if addr not in wanted:
                    stale.append(addr)
            if stale:
                self._vtysh([f"router bgp {int(m.group(1))}"] + [f"no neighbor {ipaddress.ip_address(a)}" for a in stale],
                            configure=True)
            if asn and int(m.group(1)) != asn:
                raise SpeakerRefused(f"FRR already runs BGP AS {m.group(1)}, Shield's sessions use AS {asn}; "
                                     "this FRR must be dedicated to Shield")
        if lines:
            self._vtysh(lines, configure=True)
        self._applied_hash = digest
        return {"changed": True, "peers": len(peers), "removed": stale}

    # ------------------------------------------------------------ authorisation (independent of the planner)
    def _authorise(self, db: Session, route: Route, spec: PeerSpec | None) -> None:
        net = _net(route.prefix)
        if spec is None:
            raise SpeakerRefused(f"no Shield BGP session (staging) for {route.peer}")
        try:
            aid = uuid.UUID(str(route.action_id))
        except ValueError:
            raise SpeakerRefused("announcement without a valid action id") from None
        a = db.get(MitigationAction, aid)
        if a is None or a.state not in (ActionState.EXECUTING, ActionState.ACTIVE):
            raise SpeakerRefused("announcement does not belong to an executing or active action")
        if str(a.target) != str(net):
            raise SpeakerRefused("announcement prefix differs from its action's target")
        canary = (a.plan or {}).get("acceptance_peer") == route.peer
        if spec.unaccepted and not canary:
            raise SpeakerRefused(f"production session(s) {', '.join(spec.unaccepted)} have not passed their "
                                 "acceptance run; only its canary may be announced")
        pp = db.execute(select(ProtectedPrefix).where(cast(str(net), CIDR).op("<<=")(ProtectedPrefix.prefix))).scalar_one_or_none()
        if pp is None or not (pp.enabled and pp.ownership_verified and pp.rtbh_allowed):
            raise SpeakerRefused(f"{net} is not inside a protected prefix authorised for blackholing")
        if net.prefixlen < pp.min_mitigation_prefix_len:
            raise SpeakerRefused(f"{net} is broader than /{pp.min_mitigation_prefix_len} allowed in {pp.prefix}")
        cust = db.execute(select(CustomerIpAssignment).where(
            cast(str(net), CIDR).op("<<=")(CustomerIpAssignment.address))).scalar_one_or_none()
        if cust is not None and cust.rtbh_opt_out:
            raise SpeakerRefused(f"customer {cust.customer_ref} opted out of blackholing")
        for c in route.communities:
            nv.normalise_community(c)
        want = (tuple(sorted(spec.communities)), spec.no_export, spec.planned_next_hop)
        got = (tuple(sorted(route.communities)), route.no_export, route.next_hop)
        if want != got:
            raise SpeakerRefused(f"{spec.label}'s blackhole policy changed after this action was planned; "
                                 "withdraw it and propose again")

    # ------------------------------------------------------------ Speaker interface
    def announce(self, route: Route) -> None:
        with self.sessions() as db:
            peers = self.peers(db)
            spec = peers.get(route.peer)
            self._authorise(db, route, spec)
            asn, _ = self._render(db, peers)
            net = _net(route.prefix)
            current = self._entries(spec)
            limit = min([nb.max_prefix_out for nb in spec.neighbors if nb.max_prefix_out] or [10_000])
            if str(net) not in current and len(current) >= limit:
                raise SpeakerRefused(f"{spec.label} already carries {len(current)} routes (session limit {limit})")
        self.sync()
        fam = "ip" if net.version == 4 else "ipv6"
        canary = []
        with self.sessions() as db:
            a = db.get(MitigationAction, uuid.UUID(str(route.action_id)))
            if a is not None and (a.plan or {}).get("acceptance_peer") == route.peer:
                canary = [f"{fam} prefix-list SHIELD{net.version}-ACC-{spec.tag} permit {net}"]
        self._vtysh(canary + [f"{fam} prefix-list SHIELD{net.version}-{spec.tag} permit {net}",
                     f"router bgp {asn}", f"address-family {'ipv4' if net.version == 4 else 'ipv6'} unicast",
                     f"network {net}", "exit-address-family", "exit"], configure=True)
        try:
            self.rds.hset(KEY_OWNERS, route.key, str(route.action_id))
        except redis.RedisError as e:
            log.warning("could not record route owner: %s", e)

    def withdraw(self, route: Route) -> None:
        net = _net(route.prefix)
        with self.sessions() as db:
            peers = self.peers(db)
            asn, _ = self._render(db, peers)
        try:
            tag = "int" if route.peer == "internal" else f"u{int(route.peer.split(':', 1)[1])}"
        except (IndexError, ValueError):
            raise SpeakerRefused(f"malformed peer {route.peer!r}") from None
        fam = "ip" if net.version == 4 else "ipv6"
        lines = []
        listed = self._list(f"SHIELD{net.version}-{tag}", net.version)
        if str(net) in listed:
            lines.append(f"no {fam} prefix-list SHIELD{net.version}-{tag} permit {net}")
        if str(net) in self._list(f"SHIELD{net.version}-ACC-{tag}", net.version):
            lines.append(f"no {fam} prefix-list SHIELD{net.version}-ACC-{tag} permit {net}")
        still_used = any(str(net) in self._entries(p) for p in peers.values() if p.tag != tag)
        if not still_used and asn:
            lines += [f"router bgp {asn}", f"address-family {'ipv4' if net.version == 4 else 'ipv6'} unicast",
                      f"no network {net}", "exit-address-family", "exit"]
        if lines:
            try:
                self._vtysh(lines, configure=True)
            except SpeakerError as e:
                if "Can't find" not in str(e) and "not found" not in str(e).lower():
                    raise
        try:
            self.rds.hdel(KEY_OWNERS, route.key)
        except redis.RedisError:
            pass

    def _list(self, name: str, version: int) -> list[str]:
        d = self._show_json(f"show {'ip' if version == 4 else 'ipv6'} prefix-list {name} json")
        lst = (d.get("BGP") or d.get("bgpd") or d).get(name) or {}
        return [e["prefix"] for e in lst.get("entries", []) if e.get("type") == "permit"]

    def _entries(self, spec: PeerSpec) -> list[str]:
        return self._list(f"SHIELD4-{spec.tag}", 4) + self._list(f"SHIELD6-{spec.tag}", 6)

    def routes(self) -> dict[str, Route]:
        with self.sessions() as db:
            peers = self.peers(db)
        try:
            owners = self.rds.hgetall(KEY_OWNERS)
        except redis.RedisError:
            owners = {}
        out = {}
        for p in peers.values():
            for prefix in self._entries(p):
                r = Route(peer=p.key, prefix=prefix, communities=p.communities, next_hop=p.planned_next_hop,
                          no_export=p.no_export, action_id=owners.get(f"{p.key}|{prefix}"))
                out[r.key] = r
        return out

    def verify(self, route: Route, wait: float = 5.0) -> str | None:
        """None if every session of the peer advertises the prefix with the discard next hop.
        BGP sends updates shortly after a configuration change, so an established session gets
        a few seconds before this reports a problem."""
        import time
        deadline = time.monotonic() + wait
        while True:
            problem = self._verify_once(route)
            if problem is None or time.monotonic() >= deadline or "session Established" not in problem:
                return problem
            time.sleep(0.25)

    def _verify_once(self, route: Route) -> str | None:
        with self.sessions() as db:
            spec = self.peers(db).get(route.peer)
        if spec is None:
            return f"no Shield BGP session for {route.peer}"
        net = _net(route.prefix)
        nh = spec.next_hop_v4 if net.version == 4 else spec.next_hop_v6
        afi = "ipv4" if net.version == 4 else "ipv6"
        problems = []
        for nb in [n for n in spec.neighbors if n.version == net.version] or spec.neighbors:
            d = self._show_json(f"show bgp {afi} unicast neighbors {nb.address} advertised-routes json")
            adv = (d.get("advertisedRoutes") or {}).get(str(net))
            if adv is None:
                st = self.peer_state(nb.address)
                problems.append(f"not advertised to {nb.address} (session {st})")
            elif adv.get("nextHop") and adv.get("nextHop") != nh:
                problems.append(f"advertised to {nb.address} with next hop {adv.get('nextHop')}, expected {nh}")
        return "; ".join(problems) or None

    # ------------------------------------------------------------ what is really sent (Phase 8)
    def advertised(self) -> dict[str, dict]:
        """Per configured session: its peer key and the prefixes it is advertising right now."""
        with self.sessions() as db:
            peers = self.peers(db)
        out = {}
        for p in peers.values():
            for nb in p.neighbors:
                afi = "ipv4" if nb.version == 4 else "ipv6"
                d = self._show_json(f"show bgp {afi} unicast neighbors {nb.address} advertised-routes json")
                out[nb.address] = {"peer": p.key, "name": nb.name, "environment": nb.environment,
                                   "accepted": nb.accepted,
                                   "prefixes": sorted((d.get("advertisedRoutes") or {}).keys())}
        return out

    def remove_unauthorised(self, peer_key: str, prefix: str) -> None:
        """Interlock: take a prefix off a peer whatever owns it, and re-apply Shield's policies
        in case they were altered."""
        self.withdraw(Route(peer=peer_key, prefix=prefix))
        self._applied_hash = None
        self.sync()

    def peer_state(self, address: str) -> str:
        for p in self.peer_status():
            if p["address"] == address:
                return p["state"]
        return "not configured"

    def peer_status(self) -> list[dict]:
        d = self._show_json("show bgp summary json")
        out = []
        for afi, body in d.items():
            for addr, p in ((body or {}).get("peers") or {}).items():
                out.append({"address": addr, "afi": afi, "state": p.get("state"), "remote_as": p.get("remoteAs"),
                            "uptime": p.get("peerUptime"), "prefixes_sent": p.get("pfxSnt"),
                            "description": p.get("desc")})
        return out
