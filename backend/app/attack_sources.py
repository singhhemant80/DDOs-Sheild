"""Where an attack came from: its busiest source addresses, networks (AS) and countries.

Built from ClickHouse `src_10s` (the collector's busiest sources per destination per 10-second
window) and the IP-to-ASN table. Stored on the incident when it closes, so the summary outlives
the per-source data.

Caveat shown in the dashboard: source addresses are what the packets carried. Floods such as SYN
or plain UDP floods can use forged (spoofed) sources; reflection/amplification sources are real
servers (the reflectors), not the attacker.
"""
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from . import asn as asndb
from . import telemetry as tm
from .models import AttackIncident

WINDOW_SECONDS = 10       # collector sources.window_seconds
TOP_SOURCES = 100
TOP_ASNS = 30
TOP_COUNTRIES = 20
UNKNOWN_ASN, OTHER_ASN = 4294967294, 4294967295   # collector asndb.Unknown / asndb.Other
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def _where(inc: AttackIncident) -> tuple[str, dict]:
    if inc.scope == "host":
        return "dst = {dst:String}", {"dst": str(ipaddress.ip_network(str(inc.target)).network_address)}
    return "prefix = {prefix:String}", {"prefix": str(inc.target)}


def summarize(inc: AttackIncident) -> dict:
    """Raises tm.ClickHouseUnavailable if ClickHouse cannot be read."""
    start = int(inc.first_detected_at.timestamp()) - 60
    end = int((inc.resolved_at or datetime.now(UTC)).timestamp()) + WINDOW_SECONDS
    cond, params = _where(inc)
    params |= {"since": tm.utc(start), "until": tm.utc(end), "w": WINDOW_SECONDS}
    rows = tm.ch_query(f"""
        SELECT src, max(src_as) AS exported_as, sum(pps) * {{w:UInt32}} AS packets,
               sum(bps) * {{w:UInt32}} / 8 AS bytes, max(pps) AS peak_pps, max(bps) AS peak_bps,
               argMax(proto, pps) AS proto, argMax(src_port, pps) AS src_port, argMax(dst_port, pps) AS dst_port,
               count() AS windows, min(ts) AS first_seen, max(ts) AS last_seen
        FROM src_10s WHERE {cond} AND ts >= {{since:DateTime('UTC')}} AND ts <= {{until:DateTime('UTC')}}
        GROUP BY src ORDER BY packets DESC LIMIT 5000""", params)
    agg = tm.ch_query(f"""
        SELECT max(sources) AS max_sources
        FROM src_10s WHERE {cond} AND ts >= {{since:DateTime('UTC')}} AND ts <= {{until:DateTime('UTC')}}""", params)
    nets = tm.ch_query(f"""
        SELECT asn, any(country) AS country, sum(pps) * {{w:UInt32}} AS packets, sum(bps) * {{w:UInt32}} / 8 AS bytes,
               max(sources) AS sources
        FROM asn_10s WHERE {cond} AND ts >= {{since:DateTime('UTC')}} AND ts <= {{until:DateTime('UTC')}}
        GROUP BY asn ORDER BY packets DESC LIMIT 1000""", params)
    tot = tm.ch_query(f"""
        SELECT sum(pps) AS packets FROM dst_1s
        WHERE {cond} AND ts >= {{since:DateTime('UTC')}} AND ts <= {{until:DateTime('UTC')}}""", params)
    table = asndb.table()
    total_packets = float((tot[0] if tot else {}).get("packets") or 0)
    listed = 0.0
    sources, by_as, by_cc = [], {}, {}
    for r in rows:
        exported = int(r.get("exported_as") or 0)
        info = table.lookup(r["src"]) if table else None
        asn = exported or (info.asn if info else None)
        name = info.name if info and (not exported or info.asn == exported) else (f"AS{exported}" if exported else None)
        cc = info.country if info else ""
        pk, by = float(r["packets"]), float(r["bytes"])
        listed += pk
        if len(sources) < TOP_SOURCES:
            sources.append({"ip": r["src"], "asn": asn, "as_name": name, "country": cc, "packets": round(pk),
                            "bytes": round(by), "peak_pps": round(float(r["peak_pps"])), "peak_bps": round(float(r["peak_bps"])),
                            "proto": PROTO.get(int(r["proto"]), str(r["proto"])), "src_port": int(r["src_port"]),
                            "dst_port": int(r["dst_port"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
        key = asn if asn is not None else -1
        a = by_as.setdefault(key, {"asn": asn, "as_name": name if asn is not None else "Unknown (no ASN data)",
                                   "country": cc, "packets": 0.0, "bytes": 0.0, "sources": 0})
        a["packets"] += pk
        a["bytes"] += by
        a["sources"] += 1
        if cc:
            c = by_cc.setdefault(cc, {"country": cc, "packets": 0.0, "sources": 0})
            c["packets"] += pk
            c["sources"] += 1
    full = bool(nets)
    if full:   # per-network totals from the collector cover every packet, not only listed sources
        by_as, by_cc = {}, {}
        for r in nets:
            n, cc = int(r["asn"]), r.get("country") or ""
            pk, by = float(r["packets"]), float(r["bytes"])
            if n == UNKNOWN_ASN:
                key, asn, name = -1, None, "Unknown (not in the IP-to-ASN table)"
            elif n == OTHER_ASN:
                key, asn, name = -2, None, "Smaller networks (beyond the largest 100 per 10 s)"
            else:
                info = table.by_asn(n) if table else None
                key, asn, name = n, n, (info.name if info else ("Not routed" if n == 0 else f"AS{n}"))
                cc = cc or (info.country if info else "")
            a = by_as.setdefault(key, {"asn": asn, "as_name": name, "country": cc, "packets": 0.0, "bytes": 0.0, "sources": 0})
            a["packets"] += pk
            a["bytes"] += by
            a["sources"] = max(a["sources"], int(r["sources"] or 0))
            if cc:
                c = by_cc.setdefault(cc, {"country": cc, "packets": 0.0, "sources": 0})
                c["packets"] += pk
                c["sources"] += int(r["sources"] or 0)
        listed_nets = sum(a["packets"] for a in by_as.values())
        if listed_nets > total_packets:
            total_packets = listed_nets
    base = total_packets if total_packets >= listed and total_packets > 0 else listed
    share = (lambda p: round(p / base, 4) if base else None)
    asns = sorted(by_as.values(), key=lambda a: -a["packets"])[:TOP_ASNS]
    for a in asns:
        a["share"], a["packets"], a["bytes"] = share(a["packets"]), round(a["packets"]), round(a["bytes"])
    countries = sorted(by_cc.values(), key=lambda c: -c["packets"])[:TOP_COUNTRIES]
    for c in countries:
        c["share"], c["packets"] = share(c["packets"]), round(c["packets"])
    for s in sources:
        s["share"] = share(s["packets"])
    a0 = agg[0] if agg else {}
    return {
        "available": bool(rows), "computed_at": datetime.now(UTC).isoformat(), "from": tm.utc(start), "to": tm.utc(end),
        "total_packets": round(total_packets), "listed_packets": round(listed),
        "listed_share": share(listed), "distinct_sources": len(rows), "networks_cover_all": full,
        "max_sources_per_window": int(a0.get("max_sources") or 0),
        "asn_db": asndb.status(), "sources": sources, "asns": asns, "countries": countries,
    }


def top_asns(summary: dict | None, n: int = 3) -> list[dict]:
    if not summary:
        return []
    return [{"asn": a["asn"], "as_name": a["as_name"], "share": a.get("share")}
            for a in (summary.get("asns") or [])[:n] if a.get("asn") is not None]
