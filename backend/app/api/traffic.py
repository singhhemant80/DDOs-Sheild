"""Live and historical traffic. Every value carries provenance; missing data is reported as
unavailable rather than zero."""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import time

import redis
import redis.asyncio as aredis
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import netvalidate as nv
from .. import telemetry as tm
from ..config import get_settings
from ..db import get_db, session_factory
from ..deps import Principal, authenticate_token, require
from ..models import Router, UpstreamProvider
from ..rbac import Perm, has_perm

log = logging.getLogger("shield.ws")
router = APIRouter(tags=["traffic"])


@router.get("/traffic/live")
def live(_: Principal = Depends(require(Perm.VIEW))):
    """Latest one-second snapshot: inbound/outbound totals and the top protected destinations."""
    return tm.live_snapshot()


@router.get("/traffic/history")
def live_history(seconds: int = Query(900, ge=10, le=3600), _: Principal = Depends(require(Perm.VIEW))):
    """Per-second inbound/outbound totals from the live buffer (last hour)."""
    pts = tm.history(seconds)
    return {"available": bool(pts), "points": pts}


def _step(minutes: int) -> tuple[str, int]:
    """Pick source table and bucket size so a chart gets <= ~720 points."""
    if minutes <= 360:
        return "1s", max(1, (minutes * 60) // 720)
    return "1m", max(60, ((minutes * 60) // 720 // 60) * 60)


@router.get("/traffic/totals")
def totals(minutes: int = Query(60, ge=1, le=60 * 24 * 90), _: Principal = Depends(require(Perm.VIEW))):
    src, step = _step(minutes)
    since = tm.utc(int(time.time()) - minutes * 60)
    if src == "1s":
        sql = """SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t, direction,
                        avg(pps) AS pps, avg(bps) AS bps, max(pps) AS pps_max,
                        if(countIf(provenance = 'estimated') > 0, 'estimated', 'sampled') AS provenance
                 FROM totals_1s WHERE ts >= {since:DateTime('UTC')} GROUP BY t, direction ORDER BY t"""
    else:
        sql = """SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t, direction,
                        avgMerge(pps_avg) AS pps, avgMerge(bps_avg) AS bps, maxMerge(pps_max) AS pps_max,
                        'sampled' AS provenance
                 FROM totals_1m WHERE ts >= {since:DateTime('UTC')} GROUP BY t, direction ORDER BY t"""
    try:
        rows = tm.ch_query(sql, {"step": step, "since": since})
    except tm.ClickHouseUnavailable:
        return {"available": False, "reason": "ClickHouse unavailable", "step_seconds": step, "points": []}
    return {"available": True, "source": f"totals_{src}", "step_seconds": step, "points": rows}


@router.get("/traffic/destinations/{ip}")
def destination_series(ip: str, minutes: int = Query(60, ge=1, le=60 * 24 * 90),
                       _: Principal = Depends(require(Perm.VIEW))):
    try:
        net = nv.parse_target(ip)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if net.prefixlen != net.max_prefixlen:
        raise HTTPException(422, "Expected a single address")
    addr = str(net.network_address)
    src, step = _step(minutes)
    since = tm.utc(int(time.time()) - minutes * 60)
    if src == "1s":
        sql = """SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t,
                        avg(pps) AS pps, avg(bps) AS bps, avg(tcp_pps) AS tcp_pps, avg(udp_pps) AS udp_pps,
                        avg(icmp_pps) AS icmp_pps, avg(syn_pps) AS syn_pps, avg(frag_pps) AS frag_pps,
                        max(sources_est) AS sources_est, any(provenance) AS provenance
                 FROM dst_1s WHERE dst = {dst:String} AND ts >= {since:DateTime('UTC')} GROUP BY t ORDER BY t"""
    else:
        sql = """SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND)) AS t,
                        avgMerge(pps_avg) AS pps, avgMerge(bps_avg) AS bps, maxMerge(pps_max) AS pps_max,
                        avgMerge(udp_avg) AS udp_pps, avgMerge(syn_avg) AS syn_pps
                 FROM dst_1m WHERE dst = {dst:String} AND ts >= {since:DateTime('UTC')} GROUP BY t ORDER BY t"""
    try:
        rows = tm.ch_query(sql, {"step": step, "since": since, "dst": addr})
    except tm.ClickHouseUnavailable:
        return {"available": False, "reason": "ClickHouse unavailable", "dst": addr, "points": []}
    return {"available": True, "dst": addr, "source": f"dst_{src}", "step_seconds": step, "points": rows,
            "note": "Seconds below the collector's store_min_pps threshold are not stored and appear as gaps."}


@router.get("/traffic/top")
def top_destinations(minutes: int = Query(60, ge=1, le=60 * 24 * 30), limit: int = Query(20, ge=1, le=200),
                     _: Principal = Depends(require(Perm.VIEW))):
    since = tm.utc(int(time.time()) - minutes * 60)
    sql = """SELECT dst, any(prefix) AS prefix, max(pps) AS pps_max, avg(pps) AS pps_avg, max(bps) AS bps_max,
                    max(sources_est) AS sources_max, count() AS active_seconds
             FROM dst_1s WHERE ts >= {since:DateTime('UTC')}
             GROUP BY dst ORDER BY pps_max DESC LIMIT {limit:UInt32}"""
    try:
        rows = tm.ch_query(sql, {"since": since, "limit": limit})
    except tm.ClickHouseUnavailable:
        return {"available": False, "reason": "ClickHouse unavailable", "rows": []}
    return {"available": True, "rows": rows}


@router.get("/traffic/interfaces")
def interfaces(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Measured interface rates, matched to routers (by management address) and upstreams
    (by router + interface name)."""
    routers = {str(r.mgmt_address): r for r in db.execute(select(Router)).scalars()}
    ups = db.execute(select(UpstreamProvider)).scalars().all()
    out = []
    for i in tm.interfaces():
        r = routers.get(i.get("agent", ""))
        i["router"] = r.name if r else None
        up = next((u for u in ups if r and u.router_id == r.id and u.interface_name
                   and u.interface_name == i.get("if_name")), None)
        i["upstream"] = up.name if up else None
        i["saturated"] = False
        if up and i.get("provenance") == "measured":
            cap = (up.capacity_mbps * 1e6) if up.capacity_mbps else i.get("speed_bps") or 0
            if cap:
                util = i.get("in_bps", 0) / cap
                i["in_util"] = util
                i["saturated"] = util * 100 >= up.saturation_threshold_pct
                if i["saturated"]:
                    i["advice"] = ("Link is at or near capacity. Filtering on this network cannot relieve it; "
                                   "use upstream RTBH or upstream filtering/diversion.")
        out.append(i)
    return {"interfaces": out}


@router.get("/collector/status")
def collector(_: Principal = Depends(require(Perm.VIEW))):
    return tm.collector_status()


# ---------------------------------------------------------------- WebSocket
_ws_per_user: collections.Counter[str] = collections.Counter()
MAX_WS_PER_USER = 5
REVALIDATE_SECONDS = 30


def _auth(token: str) -> tuple[str, bool]:
    db = session_factory()()
    try:
        user, _ = authenticate_token(db, token)
        return str(user.id), has_perm(user.role, Perm.VIEW)
    finally:
        db.close()


@router.websocket("/ws/traffic")
async def ws_traffic(ws: WebSocket):
    """Live stream of one-second snapshots.

    Protocol: connect, then send {"token": "<access token>"} within 5 seconds. The server replies
    {"type":"ready"} and then {"type":"traffic","data":{...}} every second. The session is
    re-validated every 30s; logout, revocation or a disabled account closes the socket (4401).
    Tokens are sent in a message, not the URL, so they never land in proxy access logs.
    """
    await ws.accept()
    try:
        msg = await asyncio.wait_for(ws.receive_json(), timeout=5)
        token = str(msg.get("token", ""))
        uid, ok = await asyncio.to_thread(_auth, token)
        if not ok:
            raise PermissionError
    except (TimeoutError, asyncio.TimeoutError, ValueError, KeyError, PermissionError, Exception):
        await ws.close(code=4401, reason="authentication required")
        return
    if _ws_per_user[uid] >= MAX_WS_PER_USER:
        await ws.close(code=4429, reason="too many live connections")
        return
    _ws_per_user[uid] += 1
    client = aredis.Redis.from_url(get_settings().redis_url, decode_responses=True, socket_connect_timeout=2)
    pubsub = client.pubsub()
    try:
        await ws.send_json({"type": "ready"})
        try:
            await pubsub.subscribe(tm.CHAN_TRAFFIC)
        except redis.RedisError:
            await ws.send_json({"type": "status", "available": False, "reason": "Redis unavailable"})
            await ws.close(code=1011)
            return

        async def drain_client():
            while True:  # we ignore client messages, but must notice disconnects
                await ws.receive_text()

        reader = asyncio.create_task(drain_client())
        last_check = time.monotonic()
        last_msg = time.monotonic()
        try:
            while not reader.done():
                m = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                now = time.monotonic()
                if m and m.get("type") == "message":
                    await ws.send_text('{"type":"traffic","data":' + m["data"] + "}")
                    last_msg = now
                elif now - last_msg > 3:
                    await ws.send_json({"type": "status", "available": False,
                                        "reason": "no live data from the collector"})
                    last_msg = now
                if now - last_check > REVALIDATE_SECONDS:
                    last_check = now
                    try:
                        await asyncio.to_thread(_auth, token)
                    except Exception:
                        await ws.close(code=4401, reason="session ended")
                        return
        finally:
            reader.cancel()
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _ws_per_user[uid] -= 1
        try:
            await pubsub.aclose()
            await client.aclose()
        except Exception:
            pass
