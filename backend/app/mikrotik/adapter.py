"""Version-aware reading of RouterOS state into one normalised shape.

Command paths and attribute names differ between RouterOS releases (most visibly BGP, which moved
from /routing/bgp/peer in v6 to /routing/bgp/connection + /routing/bgp/session in v7). Every
section is read independently: a section the router or the account cannot provide is recorded in
`errors` and the rest still works. The full routing table is never printed; routes are fetched
by query (protected prefixes, blackholes, static routes) because an edge router carries ~1M routes.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from .api import ReadOnlyClient, RouterOSError, TrapError


def b(v: str | None) -> bool:
    return str(v).lower() in ("true", "yes")


def i(v: str | None, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def duration_seconds(v: str | None) -> int | None:
    """RouterOS durations: '3w2d04:11:52', '2d03:14:07', '1h5m3s', '45s', '1m'."""
    if not v:
        return None
    s = str(v)
    total = 0
    for n, unit in re.findall(r"(\d+)([wdhms])", re.sub(r"(\d+):(\d+):(\d+)$", "", s)):
        total += int(n) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    m = re.search(r"(\d+):(\d+):(\d+)$", s)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    return total


def version_major(version: str) -> int:
    m = re.match(r"(\d+)", version or "")
    return int(m.group(1)) if m else 0


# ---------------------------------------------------------------- sections
def read_identity(c: ReadOnlyClient) -> dict:
    ident = c.print("/system/identity")
    res = c.print("/system/resource")[0]
    total, free = i(res.get("total-memory")), i(res.get("free-memory"))
    out = {
        "identity": ident[0].get("name") if ident else None,
        "version": res.get("version", ""),
        "version_major": version_major(res.get("version", "")),
        "board": res.get("board-name"),
        "architecture": res.get("architecture-name"),
        "uptime_seconds": duration_seconds(res.get("uptime")),
        "cpu_load": i(res.get("cpu-load"), -1),
        "cpu_count": i(res.get("cpu-count"), 0),
        "memory_used_pct": round(100 * (total - free) / total, 1) if total else None,
    }
    try:
        rb = c.print("/system/routerboard")[0]
        out.update(model=rb.get("model"), serial=rb.get("serial-number"), firmware=rb.get("current-firmware"))
    except (TrapError, IndexError):
        pass  # CHR / x86 have no routerboard menu
    return out


IFACE_FIELDS = ["name", "type", "running", "disabled", "comment", "rx-byte", "tx-byte", "rx-packet", "tx-packet",
                "rx-drop", "tx-drop", "rx-error", "tx-error", "link-downs", "mac-address", "mtu"]


def read_interfaces(c: ReadOnlyClient) -> list[dict]:
    out = []
    for r in c.print("/interface", proplist=IFACE_FIELDS):
        out.append({
            "name": r.get("name"), "type": r.get("type"), "running": b(r.get("running")),
            "disabled": b(r.get("disabled")), "comment": r.get("comment") or None, "mac": r.get("mac-address"),
            "rx_byte": i(r.get("rx-byte")), "tx_byte": i(r.get("tx-byte")),
            "rx_packet": i(r.get("rx-packet")), "tx_packet": i(r.get("tx-packet")),
            "rx_drop": i(r.get("rx-drop")), "tx_drop": i(r.get("tx-drop")),
            "rx_error": i(r.get("rx-error")), "tx_error": i(r.get("tx-error")), "link_downs": i(r.get("link-downs")),
        })
    return out


def read_addresses(c: ReadOnlyClient) -> list[dict]:
    return [{"address": r.get("address"), "interface": r.get("interface"), "disabled": b(r.get("disabled")),
             "dynamic": b(r.get("dynamic"))} for r in c.print("/ip/address")]


def read_bgp(c: ReadOnlyClient, major: int) -> dict:
    if major >= 7:
        conns = [{
            "name": r.get("name"), "remote_address": (r.get("remote.address") or "").split("/")[0],
            "remote_as": i(r.get("remote.as"), 0) or None, "local_as": i(r.get("as") or r.get("local.as"), 0) or None,
            "role": r.get("local.role"), "disabled": b(r.get("disabled")),
            "input_filter": r.get("input.filter"), "output_filter": r.get("output.filter-chain"),
        } for r in c.print("/routing/bgp/connection")]
        sessions = []
        for r in c.print("/routing/bgp/session"):
            established = b(r.get("established")) or "E" in (r.get("flags") or "")
            sessions.append({
                "name": r.get("name"), "remote_address": (r.get("remote.address") or "").split("/")[0],
                "remote_as": i(r.get("remote.as"), 0) or None, "local_address": r.get("local.address"),
                "established": established, "state": "established" if established else (r.get("state") or "down"),
                "uptime_seconds": duration_seconds(r.get("uptime")),
                "prefixes_received": i(r.get("prefix-count"), 0),
            })
        # A configured connection with no session row is not established.
        seen = {s["remote_address"] for s in sessions}
        for cn in conns:
            if not cn["disabled"] and cn["remote_address"] not in seen:
                sessions.append({"name": cn["name"], "remote_address": cn["remote_address"],
                                 "remote_as": cn["remote_as"], "local_address": None, "established": False,
                                 "state": "idle", "uptime_seconds": None, "prefixes_received": 0})
        return {"connections": conns, "sessions": sessions}
    # RouterOS 6
    peers = c.print("/routing/bgp/peer")
    sessions = [{
        "name": r.get("name"), "remote_address": r.get("remote-address"), "remote_as": i(r.get("remote-as"), 0) or None,
        "local_address": r.get("local-address"), "established": (r.get("state") == "established"),
        "state": r.get("state") or "idle", "uptime_seconds": duration_seconds(r.get("uptime")),
        "prefixes_received": i(r.get("prefix-count"), 0),
    } for r in peers]
    conns = [{"name": s["name"], "remote_address": s["remote_address"], "remote_as": s["remote_as"],
              "local_as": None, "role": None, "disabled": False, "input_filter": None, "output_filter": None}
             for s in sessions]
    return {"connections": conns, "sessions": sessions}


def _route(r: dict) -> dict:
    return {
        "dst": r.get("dst-address"), "gateway": r.get("gateway") or r.get("immediate-gw"),
        "distance": i(r.get("distance"), 0), "table": r.get("routing-table", "main"),
        "active": b(r.get("active")), "blackhole": b(r.get("blackhole")) or r.get("type") == "blackhole",
        "static": b(r.get("static")) or not any(b(r.get(k)) for k in ("bgp", "ospf", "dynamic", "connect")),
        "bgp": b(r.get("bgp")), "comment": r.get("comment") or None,
        "communities": r.get("bgp.communities") or None,
    }


def read_routes(c: ReadOnlyClient, protected: list[str]) -> list[dict]:
    """Routes that matter to Shield: anything inside or equal to a protected prefix, and blackholes."""
    nets = [ipaddress.ip_network(p) for p in protected]
    found: dict[tuple, dict] = {}

    def keep(r: dict, force: bool = False):
        dst = r.get("dst-address")
        try:
            n = ipaddress.ip_network(dst)
        except (TypeError, ValueError):
            return
        if force or any(n.version == p.version and (n.subnet_of(p) or p.subnet_of(n) and n == p) for p in nets):
            nr = _route(r)
            found[(nr["dst"], nr["table"], nr["gateway"], nr["blackhole"])] = nr

    for p in protected:
        for r in c.print("/ip/route", queries=[f"dst-address={p}"]):
            keep(r)
    for r in c.print("/ip/route", queries=["blackhole=true"]):
        keep(r, force=True)
    for r in c.print("/ip/route", queries=["static=true"]):
        keep(r)
    return sorted(found.values(), key=lambda r: (ipaddress.ip_network(r["dst"]).version,
                                                 ipaddress.ip_network(r["dst"])))


def read_traffic_flow(c: ReadOnlyClient) -> dict:
    cfg = (c.print("/ip/traffic-flow") or [{}])[0]
    targets = c.print("/ip/traffic-flow/target")
    return {
        "enabled": b(cfg.get("enabled")), "interfaces": cfg.get("interfaces", ""),
        "active_timeout_seconds": duration_seconds(cfg.get("active-flow-timeout")),
        "inactive_timeout_seconds": duration_seconds(cfg.get("inactive-flow-timeout")),
        "cache_entries": cfg.get("cache-entries"), "sampling": b(cfg.get("packet-sampling")),
        # RouterOS: sampling-interval packets are sampled, then sampling-space packets are skipped
        # (RFC 5476 packet interval/space), so 1 in N = (interval + space) / interval.
        "sampling_interval": i(cfg.get("sampling-interval"), 0), "sampling_space": i(cfg.get("sampling-space"), 0),
        "sampling_rate": ((i(cfg.get("sampling-interval"), 0) + i(cfg.get("sampling-space"), 0)) // i(cfg.get("sampling-interval"), 0))
                         if b(cfg.get("packet-sampling")) and i(cfg.get("sampling-interval"), 0) > 0 else None,
        "targets": [{"address": t.get("dst-address"), "port": i(t.get("port"), 0), "version": t.get("version"),
                     "src_address": t.get("src-address") or None, "disabled": b(t.get("disabled"))} for t in targets],
    }


def read_services(c: ReadOnlyClient) -> list[dict]:
    return [{"name": r.get("name"), "port": i(r.get("port"), 0), "disabled": b(r.get("disabled")),
             "address": r.get("address") or ""} for r in c.print("/ip/service")]


def read_l3hw(c: ReadOnlyClient) -> list[dict]:
    """CCR2116/2216 switch chips can route in hardware; traffic-flow does not see those packets."""
    return [{"name": r.get("name"), "l3_hw_offloading": b(r.get("l3-hw-offloading"))}
            for r in c.print("/interface/ethernet/switch")]


# Policies that let an account change the router. Shield's account needs only read, api and test.
WRITE_POLICIES = ("write", "policy", "reboot", "sensitive", "password", "ftp", "sniff", "romon", "rest-api")


def read_permissions(c: ReadOnlyClient, username: str) -> dict:
    users = c.print("/user", proplist=["name", "group", "address", "disabled"], queries=[f"name={username}"])
    if not users:
        return {"username": username, "group": None, "policies": [], "write_policies": [], "address": None}
    group = users[0].get("group")
    rows = c.print("/user/group", proplist=["name", "policy"], queries=[f"name={group}"]) if group else []
    pol = [p for p in (rows[0].get("policy", "") if rows else "").split(",") if p]
    granted = [p for p in pol if not p.startswith("!")]
    return {"username": username, "group": group, "policies": granted,
            "write_policies": [p for p in granted if p in WRITE_POLICIES],
            "address": users[0].get("address") or None}


# ---------------------------------------------------------------- collection
def collect(c: ReadOnlyClient, *, full: bool, protected: list[str], username: str | None = None) -> dict[str, Any]:
    snap: dict[str, Any] = {"errors": {}}

    def section(name: str, fn, *a):
        try:
            snap[name] = fn(c, *a)
        except TrapError as e:
            snap["errors"][name] = str(e)
        except (KeyError, IndexError, ValueError) as e:
            snap["errors"][name] = f"unexpected reply: {e}"

    section("system", read_identity)
    major = (snap.get("system") or {}).get("version_major", 7)
    section("interfaces", read_interfaces)
    if full:
        section("addresses", read_addresses)
        section("bgp", read_bgp, major)
        section("routes", read_routes, protected)
        section("traffic_flow", read_traffic_flow)
        section("services", read_services)
        section("switch", read_l3hw)
        if username:
            section("permissions", read_permissions, username)
    return snap


# ---------------------------------------------------------------- findings
def findings(snap: dict, *, mgmt_address: str, model: str, collector_address: str | None,
             tls_verified_by: str) -> list[dict]:
    """Checks that matter for DDoS visibility and for the safety of Shield's own access."""
    out: list[dict] = []
    add = lambda level, code, msg: out.append({"level": level, "code": code, "message": msg})  # noqa: E731

    sysinfo = snap.get("system") or {}
    if sysinfo and sysinfo.get("version_major", 7) < 7:
        add("warn", "routeros_v6", "RouterOS 6 is supported for monitoring only; BGP and mitigation need RouterOS 7.")

    tf = snap.get("traffic_flow")
    if tf is not None:
        if not tf["enabled"]:
            add("error", "flow_disabled", "Traffic-flow export is off: Shield sees no flows from this router.")
        active = [t for t in tf["targets"] if not t["disabled"]]
        if not active:
            add("error", "flow_no_target", "No traffic-flow target is configured.")
        if collector_address and active and not any(t["address"] == collector_address for t in active):
            add("error", "flow_wrong_target",
                f"No traffic-flow target points at Shield's collector ({collector_address}).")
        if any(t["version"] in ("1", "5") for t in active):
            add("warn", "flow_v5", "NetFlow v5 cannot carry IPv6 or the sampling rate; use IPFIX or version 9.")
        if any(t["src_address"] not in (None, mgmt_address) for t in active) or any(t["src_address"] is None for t in active):
            add("warn", "flow_src",
                f"Set the target's src-address to {mgmt_address}; the collector only accepts listed exporter addresses.")
        if tf["sampling"] and tf["sampling_interval"] > 0 and tf["sampling_space"] == 0:
            add("warn", "flow_sampling_space",
                "Packet sampling is on but sampling-space is 0, so every packet is still exported. "
                "For 1 in 1024 set sampling-interval=1 sampling-space=1023.")
        if tf["enabled"] and not tf["sampling"]:
            add("warn", "flow_unsampled",
                "Packet sampling is off. During a large attack unsampled export can overload the router CPU and the collector.")
        if (tf["active_timeout_seconds"] or 0) > 60:
            add("warn", "flow_timeout",
                f"Active flow timeout is {tf['active_timeout_seconds']} s; 1 minute or less gives faster detection.")
        if tf["interfaces"] in ("", "all"):
            add("warn", "flow_all_interfaces",
                "Export is enabled on all interfaces; traffic crossing two of them is counted twice. "
                "Export only on the upstream-facing interfaces.")
        if tf["enabled"] and active and not any(x["code"].startswith("flow") for x in out):
            add("ok", "flow_ok", "Traffic-flow export is configured.")

    sw = snap.get("switch") or []
    if any(s["l3_hw_offloading"] for s in sw):
        add("warn", "l3hw",
            "Layer-3 hardware offloading is on: packets routed by the switch chip are not seen by traffic-flow, so "
            "attacks through those ports can be invisible. Disabling it on upstream ports moves forwarding to the "
            "CPU, which has far less capacity; check the expected traffic first (see docs/mikrotik.md).")

    perm = snap.get("permissions")
    if perm is not None:
        if perm["group"] is None:
            add("warn", "perm_unknown", f"Could not find the account {perm['username']!r} in /user.")
        elif perm["write_policies"]:
            add("error", "perm_write",
                f"The account {perm['username']!r} (group {perm['group']}) can change the router "
                f"({', '.join(perm['write_policies'])}). Shield never writes in read-only mode, but a leaked "
                "credential could; use a group with only read,api,test.")
        else:
            add("ok", "perm_ok", f"The account {perm['username']!r} is read-only (group {perm['group']}).")
        if perm["group"] is not None and not perm["address"]:
            add("warn", "perm_any_address", "The account may log in from any address; set its allowed address to the Shield server.")

    for s in snap.get("services") or []:
        if s["name"] == "api" and not s["disabled"]:
            add("warn", "api_plain", "The unencrypted API service is enabled; Shield needs only api-ssl.")
        if s["name"] == "api-ssl" and not s["disabled"] and s["address"] in ("", "0.0.0.0/0"):
            add("warn", "api_open", "api-ssl accepts connections from any address; restrict it to the Shield server.")
    if tls_verified_by == "none":
        add("warn", "tls_unverified",
            "Shield is not verifying this router's certificate. Pin it on the router page.")
    elif tls_verified_by == "plain":
        add("warn", "tls_plain", "Shield connects without TLS; credentials cross the network in clear text.")

    for name, err in (snap.get("errors") or {}).items():
        add("warn", f"read_{name}", f"Could not read {name.replace('_', ' ')}: {err}")
    return out


__all__ = ["collect", "findings", "duration_seconds", "RouterOSError"]
