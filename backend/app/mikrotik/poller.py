"""shield-mikrotik: read-only poller for MikroTik RouterOS v7 routers.

Every enabled router that has API credentials is polled on three tiers:

    interfaces   every 10 s   identity/resource + interface counters -> live interface rates
    bgp          every 30 s   the above + BGP connections/sessions
    full         every 60 s   everything: addresses, routes for protected prefixes, traffic-flow,
                              services, switch offload, account permissions -> checks

Results
- router_state row (latest snapshot + checks), routers.status / identity / version / last_seen_at
- router_events rows + a {"type": "router_event"} message on shield:events for: unreachable (after
  3 consecutive failures), recovered, bgp_down, bgp_up, reboot, version_change
- bgp_neighbors.last_state for inventory neighbors on this router
- interface rates to Redis HASH shield:ifaces ("<mgmt>|<name>", source "routeros", provenance
  "measured") and to ClickHouse iface_1s
- status heartbeat in shield:mikrotik:status

Nothing here can change a router: the client refuses any command that is not a print.
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable

import httpx
import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import security
from ..changes import get_setting
from ..config import get_settings
from ..db import session_factory
from ..models import BgpNeighbor, DeviceStatus, ProtectedPrefix, Router, RouterEvent, RouterState, Severity
from . import adapter
from .api import ConnectError, LoginError, ReadOnlyClient, RouterOSError, TLSUntrusted

log = logging.getLogger("shield.mikrotik")

CHAN_EVENTS = "shield:events"
KEY_IFACES = "shield:ifaces"
KEY_STATUS = "shield:mikrotik:status"
TIERS = {"interfaces": 10, "bgp": 30, "full": 60}
DOWN_AFTER = 3
RELOAD_EVERY = 30
MAX_WORKERS = 8


def _now() -> datetime:
    return datetime.now(UTC)


def if_index(name: str) -> int:
    """RouterOS has no SNMP-style ifIndex in the API; derive a stable one from the name."""
    return zlib.crc32(name.encode()) & 0x7FFFFFFF


def merge_bgp(bgp: dict) -> list[dict]:
    """One row per configured connection with the matching session's state (v7 names sessions
    '<connection>-N'); sessions with no connection are listed too."""
    sessions = list(bgp.get("sessions") or [])
    out = []
    for conn in bgp.get("connections") or []:
        match = next((s for s in sessions if s["remote_address"] == conn["remote_address"]
                      and (s["name"] == conn["name"] or s["name"].startswith(conn["name"] + "-"))), None)
        if match is None:
            match = next((s for s in sessions if s["remote_address"] == conn["remote_address"]), None)
        if match:
            sessions.remove(match)
        out.append({**conn, "state": (match or {}).get("state") or ("disabled" if conn["disabled"] else "idle"),
                    "established": bool(match and match["established"]),
                    "uptime_seconds": (match or {}).get("uptime_seconds"),
                    "prefixes_received": (match or {}).get("prefixes_received") if match and match["established"] else None,
                    "local_address": (match or {}).get("local_address")})
    for s in sessions:
        out.append({"name": s["name"], "remote_address": s["remote_address"], "remote_as": s["remote_as"],
                    "local_as": None, "role": None, "disabled": False, "input_filter": None, "output_filter": None,
                    **{k: s.get(k) for k in ("state", "established", "uptime_seconds", "prefixes_received", "local_address")}})
    return out


@dataclass
class Counters:
    t: float
    values: dict[str, tuple[int, int, int, int]]


@dataclass
class RouterRuntime:
    id: int
    name: str
    mgmt: str
    model: str
    target: dict
    username: str
    client: ReadOnlyClient | None = None
    next_due: dict[str, float] = field(default_factory=lambda: {t: 0.0 for t in TIERS})
    counters: Counters | None = None
    uptime: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class MikroTikPoller:
    def __init__(self, rds: redis.Redis | None = None, sessions: Callable[[], Session] | None = None,
                 clock: Callable[[], float] = time.time, ch_insert: Callable[[list[dict]], None] | None = None):
        s = get_settings()
        self.rds = rds or redis.Redis.from_url(s.redis_url, socket_timeout=2, socket_connect_timeout=2,
                                               decode_responses=True)
        self.sessions = sessions or session_factory()
        self.clock = clock
        self.ch_insert = ch_insert or self._ch_insert
        self.routers: dict[int, RouterRuntime] = {}
        self.last_reload = 0.0
        self.polls = 0
        self.failures = 0
        self.started = clock()

    # ------------------------------------------------------------ inventory
    def reload(self) -> None:
        with self.sessions() as db:
            rows = db.execute(select(Router).where(Router.enabled)).scalars().all()
            seen = set()
            for r in rows:
                if not (r.api_username and r.api_password_enc):
                    continue
                target = {"host": str(r.mgmt_address), "port": r.api_port, "use_tls": r.use_tls,
                          "verify_tls": r.verify_tls, "fingerprint": r.tls_fingerprint,
                          "pw": r.api_password_enc, "user": r.api_username}
                seen.add(r.id)
                cur = self.routers.get(r.id)
                if cur and cur.target == target:
                    cur.name, cur.model = r.name, r.model.value
                    continue
                if cur:
                    self._drop_client(cur)
                self.routers[r.id] = RouterRuntime(r.id, r.name, str(r.mgmt_address), r.model.value, target, r.api_username)
            for rid in set(self.routers) - seen:
                self._drop_client(self.routers.pop(rid))
        self.last_reload = self.clock()

    @staticmethod
    def _drop_client(rt: RouterRuntime) -> None:
        if rt.client:
            rt.client.close()
            rt.client = None

    def _client(self, rt: RouterRuntime) -> ReadOnlyClient:
        if rt.client and rt.client.sock:
            return rt.client
        t = rt.target
        try:
            password = security.decrypt_secret(t["pw"])
        except Exception as e:  # missing/rotated SHIELD_CREDENTIAL_KEY
            raise LoginError(f"cannot decrypt the stored password ({type(e).__name__}); re-enter it") from None
        rt.client = ReadOnlyClient(t["host"], t["port"], t["user"], password, use_tls=t["use_tls"],
                                   verify_tls=t["verify_tls"], fingerprint=t["fingerprint"]).connect()
        return rt.client

    # ------------------------------------------------------------ polling
    def due(self) -> list[tuple[RouterRuntime, str]]:
        now = self.clock()
        out = []
        for rt in self.routers.values():
            tier = next((t for t in ("full", "bgp", "interfaces") if rt.next_due[t] <= now), None)
            if tier:
                out.append((rt, tier))
        return out

    def poll(self, rt: RouterRuntime, tier: str) -> dict:
        """Poll one router once. Returns a summary (used by tests and the probe)."""
        if not rt.lock.acquire(blocking=False):
            return {"skipped": True}
        try:
            now = self.clock()
            # A higher tier includes the lower ones.
            for t, every in TIERS.items():
                if list(TIERS).index(t) <= list(TIERS).index(tier):
                    rt.next_due[t] = now + every
            protected: list[str] = []
            if tier == "full":
                with self.sessions() as db:
                    protected = [str(p) for p in db.execute(select(ProtectedPrefix.prefix)
                                                            .where(ProtectedPrefix.enabled)).scalars()]
            try:
                c = self._client(rt)
                snap = adapter.collect(c, full=tier == "full", protected=protected,
                                       username=rt.username if tier == "full" else None)
                if tier == "bgp":
                    major = (snap.get("system") or {}).get("version_major", 7)
                    try:
                        snap["bgp"] = adapter.read_bgp(c, major)
                    except RouterOSError as e:
                        snap["errors"]["bgp"] = str(e)
                tls = c.tls.verified_by
                latency = c.last_latency_ms
            except RouterOSError as e:
                self._drop_client(rt)
                self.failures += 1
                return self._record_failure(rt, e)
            self.polls += 1
            up = (snap.get("system") or {}).get("uptime_seconds")
            if up is not None and rt.uptime is not None and up + 30 < rt.uptime:
                rt.counters = None  # rebooted: counters restarted from zero
            rt.uptime = up if up is not None else rt.uptime
            rates = self._rates(rt, snap.get("interfaces"), now)
            return self._record_success(rt, tier, snap, tls, latency, rates)
        finally:
            rt.lock.release()

    def _rates(self, rt: RouterRuntime, ifaces: list[dict] | None, now: float) -> list[dict]:
        if not ifaces:
            return []
        cur = {i["name"]: (i["rx_byte"], i["tx_byte"], i["rx_packet"], i["tx_packet"]) for i in ifaces}
        prev, rt.counters = rt.counters, Counters(now, cur)
        if prev is None or now - prev.t < 1:
            return []
        dt = now - prev.t
        running = {i["name"]: i["running"] for i in ifaces}
        out = []
        for name, v in cur.items():
            p = prev.values.get(name)
            if p is None or any(a < b for a, b in zip(v, p)):  # new interface or counter reset (reboot)
                continue
            rx, tx, rxp, txp = ((a - b) / dt for a, b in zip(v, p))
            out.append({"agent": rt.mgmt, "if_index": if_index(name), "if_name": name, "speed_bps": 0,
                        "oper_up": running[name], "in_bps": rx * 8, "out_bps": tx * 8, "in_pps": rxp,
                        "out_pps": txp, "in_util": 0, "out_util": 0, "ts": int(now),
                        "source": "routeros", "provenance": "measured", "router_id": rt.id})
        if out:
            try:
                self.rds.hset(KEY_IFACES, mapping={f"{r['agent']}|{r['if_name']}": json.dumps(r) for r in out})
            except redis.RedisError as e:
                log.warning("redis unavailable: %s", e)
            try:
                self.ch_insert(out)
            except Exception as e:  # history is best-effort
                log.warning("clickhouse insert failed: %s", e)
        return out

    @staticmethod
    def _ch_insert(rows: list[dict]) -> None:
        s = get_settings()
        body = "\n".join(json.dumps({
            "ts": r["ts"], "agent": r["agent"], "if_index": r["if_index"], "if_name": r["if_name"],
            "in_bps": r["in_bps"], "out_bps": r["out_bps"], "in_pps": r["in_pps"], "out_pps": r["out_pps"],
            "speed_bps": r["speed_bps"], "source": r["source"]}) for r in rows)
        resp = httpx.post(s.clickhouse_url, params={
            "query": f"INSERT INTO {s.clickhouse_database}.iface_1s FORMAT JSONEachRow",
            "date_time_input_format": "best_effort"}, content=body.encode(), timeout=10,
            headers={"X-ClickHouse-User": s.clickhouse_user, "X-ClickHouse-Key": s.clickhouse_password})
        if resp.status_code != 200:
            raise RuntimeError(resp.text[:200])

    # ------------------------------------------------------------ persistence
    def _event(self, db: Session, rt: RouterRuntime, kind: str, severity: Severity, message: str,
               detail: dict | None = None) -> None:
        at = _now()
        db.add(RouterEvent(router_id=rt.id, at=at, kind=kind, severity=severity, message=message, detail=detail or {}))
        try:
            self.rds.publish(CHAN_EVENTS, json.dumps({
                "type": "router_event", "router_id": rt.id, "router": rt.name, "kind": kind,
                "severity": severity.value, "message": message, "at": at.isoformat()}))
        except redis.RedisError:
            pass

    def _record_failure(self, rt: RouterRuntime, e: RouterOSError) -> dict:
        detail = {"kind": e.kind}
        if isinstance(e, TLSUntrusted) and e.fingerprint:
            detail["presented_fingerprint"] = e.fingerprint
        with self.sessions() as db, db.begin():
            st = db.get(RouterState, rt.id)
            if st is None:
                st = RouterState(router_id=rt.id, polled_at=_now(), ok=False, consecutive_failures=0)
                db.add(st)
            st.polled_at, st.ok, st.error = _now(), False, str(e)
            st.consecutive_failures = (st.consecutive_failures or 0) + 1
            st.permissions = {**(st.permissions or {}), "last_error": detail}
            r = db.get(Router, rt.id)
            if st.consecutive_failures == DOWN_AFTER or (st.consecutive_failures == 1 and e.kind in ("auth", "tls_untrusted")):
                self._event(db, rt, "unreachable", Severity.HIGH,
                            f"{rt.name} is not answering: {e}" if e.kind not in ("auth", "tls_untrusted")
                            else f"Shield cannot log in to {rt.name}: {e}", detail)
            if r is not None and (st.consecutive_failures >= DOWN_AFTER or e.kind in ("auth", "tls_untrusted")):
                r.status = DeviceStatus.DOWN
        log.info("%s: %s", rt.name, e)
        return {"ok": False, "error": str(e), "kind": e.kind}

    def _record_success(self, rt: RouterRuntime, tier: str, snap: dict, tls: str, latency: float | None,
                        rates: list[dict]) -> dict:
        sysinfo = snap.get("system") or {}
        with self.sessions() as db, db.begin():
            r = db.get(Router, rt.id)
            st = db.get(RouterState, rt.id)
            fresh = st is None
            if fresh:
                st = RouterState(router_id=rt.id, polled_at=_now(), ok=True, consecutive_failures=0)
                db.add(st)
            if not fresh and st.consecutive_failures >= DOWN_AFTER or (not fresh and not st.ok and
                                                                    r is not None and r.status == DeviceStatus.DOWN):
                self._event(db, rt, "recovered", Severity.INFO, f"{rt.name} is reachable again.")
            if not fresh and sysinfo:
                if st.uptime_seconds and sysinfo.get("uptime_seconds") is not None \
                        and sysinfo["uptime_seconds"] + 30 < st.uptime_seconds:
                    self._event(db, rt, "reboot", Severity.MEDIUM,
                                f"{rt.name} restarted (uptime {sysinfo['uptime_seconds']} s).")
                if st.version and sysinfo.get("version") and sysinfo["version"] != st.version:
                    self._event(db, rt, "version_change", Severity.LOW,
                                f"{rt.name} now runs RouterOS {sysinfo['version']} (was {st.version}).",
                                {"from": st.version, "to": sysinfo["version"]})
            st.polled_at, st.ok, st.error, st.consecutive_failures = _now(), True, None, 0
            if sysinfo:
                st.identity, st.version, st.board = sysinfo.get("identity"), sysinfo.get("version"), sysinfo.get("board")
                st.uptime_seconds, st.cpu_load = sysinfo.get("uptime_seconds"), sysinfo.get("cpu_load")
                st.resources = {**sysinfo, "api_latency_ms": latency, "tls": tls}
            if "interfaces" in snap:
                by_name = {x["if_name"]: x for x in rates}
                st.interfaces = [{**i, **({k: by_name[i["name"]][k] for k in ("in_bps", "out_bps", "in_pps", "out_pps")}
                                          if i["name"] in by_name else {})} for i in snap["interfaces"]]
            if "bgp" in snap:
                peers = merge_bgp(snap["bgp"])
                self._bgp_changes(db, rt, st.bgp if not fresh else None, peers)
                st.bgp = peers
            if tier == "full":
                collector = get_setting(db, "collector_address", "") or None
                st.addresses = snap.get("addresses", st.addresses or [])
                if "routes" in snap:
                    st.routes = {"items": snap["routes"]}
                if "traffic_flow" in snap:
                    st.traffic_flow = snap["traffic_flow"]
                st.permissions = {**(snap.get("permissions") or {}), "services": snap.get("services") or [],
                                  "switch": snap.get("switch") or [], "errors": snap.get("errors") or {}}
                st.checks = adapter.findings(snap, mgmt_address=rt.mgmt, model=rt.model,
                                             collector_address=collector, tls_verified_by=tls)
            if r is not None:
                r.last_seen_at = _now()
                if sysinfo:
                    r.identity, r.routeros_version = sysinfo.get("identity"), (sysinfo.get("version") or "")[:32] or None
                degraded = bool(snap.get("errors")) or any(not p["established"] and not p["disabled"] for p in st.bgp or [])
                r.status = DeviceStatus.DEGRADED if degraded else DeviceStatus.UP
        return {"ok": True, "tier": tier, "errors": snap.get("errors"), "rates": len(rates)}

    def _bgp_changes(self, db: Session, rt: RouterRuntime, before: list | None, peers: list[dict]) -> None:
        prev = {p["remote_address"]: p for p in before or []}
        for p in peers:
            old = prev.get(p["remote_address"])
            if old is not None and old.get("established") != p["established"] and not p["disabled"]:
                if p["established"]:
                    self._event(db, rt, "bgp_up", Severity.INFO,
                                f"BGP session {p['name']} to {p['remote_address']} (AS{p['remote_as']}) is established.",
                                {"peer": p["remote_address"]})
                else:
                    self._event(db, rt, "bgp_down", Severity.HIGH,
                                f"BGP session {p['name']} to {p['remote_address']} (AS{p['remote_as']}) went down"
                                + (f" (now {p['state']})." if p["state"] not in ("down", "") else "."), {"peer": p["remote_address"], "state": p["state"]})
        by_addr = {p["remote_address"]: p for p in peers}
        for n in db.execute(select(BgpNeighbor).where(BgpNeighbor.router_id == rt.id)).scalars():
            p = by_addr.get(str(n.neighbor_address))
            state = (p["state"] if p else "not_configured")[:32]
            if n.last_state != state:
                n.last_state, n.last_state_change_at = state, _now()

    # ------------------------------------------------------------ service
    def publish_status(self) -> None:
        try:
            self.rds.set(KEY_STATUS, json.dumps({
                "ts": int(self.clock()), "started": int(self.started), "routers": len(self.routers),
                "polls": self.polls, "failures": self.failures}), ex=60)
        except redis.RedisError:
            pass

    def run(self) -> None:
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        log.info("mikrotik poller started (read-only)")
        inflight: set[int] = set()
        with ThreadPoolExecutor(MAX_WORKERS, thread_name_prefix="router") as pool:
            while not stop.is_set():
                if self.clock() - self.last_reload >= RELOAD_EVERY:
                    try:
                        self.reload()
                    except Exception:
                        log.exception("could not load routers")
                for rt, tier in self.due():
                    if rt.id in inflight:
                        continue
                    inflight.add(rt.id)

                    def job(rt=rt, tier=tier):
                        try:
                            self.poll(rt, tier)
                        except Exception:
                            log.exception("poll of %s failed", rt.name)
                        finally:
                            inflight.discard(rt.id)
                    pool.submit(job)
                self.publish_status()
                stop.wait(1)
        for rt in self.routers.values():
            self._drop_client(rt)
        log.info("mikrotik poller stopped")


# ---------------------------------------------------------------- CLI
def probe(host: str, port: int, user: str, password: str, *, use_tls: bool, verify_tls: bool,
          fingerprint: str | None, mgmt: str | None, collector: str | None, model: str = "") -> dict[str, Any]:
    with ReadOnlyClient(host, port, user, password, use_tls=use_tls, verify_tls=verify_tls,
                        fingerprint=fingerprint) as c:
        snap = adapter.collect(c, full=True, protected=[], username=user)
        tls = c.tls.verified_by
    snap["bgp_peers"] = merge_bgp(snap.get("bgp") or {})
    snap["checks"] = adapter.findings(snap, mgmt_address=mgmt or host, model=model, collector_address=collector,
                                      tls_verified_by=tls)
    snap["tls"] = tls
    return snap


def main(argv=None) -> int:
    import argparse
    import getpass
    import sys

    from .api import fetch_certificate
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    ap = argparse.ArgumentParser(prog="shield-mikrotik", description="Read-only MikroTik RouterOS poller")
    sub = ap.add_subparsers(dest="cmd")
    pr = sub.add_parser("probe", help="connect once, print what Shield would read and the checks")
    cert = sub.add_parser("cert", help="show the router's API-SSL certificate fingerprint (sends no credentials)")
    for p in (pr, cert):
        p.add_argument("host")
        p.add_argument("--port", type=int, default=8729)
    pr.add_argument("--user", required=True)
    pr.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    pr.add_argument("--plain", action="store_true", help="plain API (port 8728); credentials are sent unencrypted")
    pr.add_argument("--fingerprint", help="pin the certificate (SHA-256, 'AB:CD:...')")
    pr.add_argument("--insecure", action="store_true", help="do not verify the certificate")
    pr.add_argument("--collector", help="expected traffic-flow target, e.g. 10.0.0.5:2055")
    pr.add_argument("--json", action="store_true")
    sub.add_parser("simulate", help="run a RouterOS API simulator for lab testing", add_help=False)
    args, rest = ap.parse_known_args(argv)
    if args.cmd == "simulate":
        from .simulator import main as sim_main
        return sim_main(rest)
    if rest:
        ap.error(f"unrecognised arguments: {' '.join(rest)}")
    try:
        if args.cmd == "cert":
            info = fetch_certificate(args.host, args.port)
            for k, v in info.items():
                if k != "fingerprint_hex":
                    print(f"{k:12} {v}")
            print("\nCompare with: /certificate print detail  (fingerprint) on the router, then pin it in Shield.")
            return 0
        if args.cmd == "probe":
            pw = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Password: ")
            snap = probe(args.host, args.port, args.user, pw, use_tls=not args.plain, verify_tls=not args.insecure,
                         fingerprint=args.fingerprint, mgmt=None, collector=args.collector)
            if args.json:
                print(json.dumps(snap, indent=2, default=str))
                return 0
            s = snap.get("system") or {}
            print(f"{s.get('identity')}  RouterOS {s.get('version')}  {s.get('board')}  up {s.get('uptime_seconds')} s  "
                  f"cpu {s.get('cpu_load')}%  tls={snap['tls']}")
            for p in snap["bgp_peers"]:
                print(f"  bgp {p['name']:20} {p['remote_address']:>16} AS{p['remote_as']:<8} {p['state']}")
            for f in snap["checks"]:
                print(f"  [{f['level']:5}] {f['message']}")
            return 0
    except TLSUntrusted as e:
        print(f"error: {e}", file=sys.stderr)
        if e.fingerprint:
            from .api import colon_fingerprint
            print(f"presented certificate: {colon_fingerprint(e.fingerprint)}", file=sys.stderr)
        return 2
    except (ConnectError, LoginError, RouterOSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    MikroTikPoller().run()
    return 0
