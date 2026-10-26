"""Access to live (Redis) and historical (ClickHouse) traffic data.

Key names mirror collector/internal/output/output.go - keep them in sync.
Every function degrades gracefully: callers get None / [] plus an "unavailable" marker
instead of an exception when a backing store is down.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import ProtectedPrefix

log = logging.getLogger("shield.telemetry")

KEY_PREFIXES = "shield:config:prefixes"
CHAN_TRAFFIC = "shield:traffic"
KEY_LATEST = "shield:traffic:latest"
KEY_HISTORY = "shield:traffic:history"
KEY_IFACES = "shield:ifaces"
KEY_COLLECTOR = "shield:collector:status"

_redis: redis.Redis | None = None


def rds() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(get_settings().redis_url, socket_timeout=2, socket_connect_timeout=2,
                                      decode_responses=True, health_check_interval=30)
    return _redis


def reset_clients() -> None:  # tests
    global _redis
    _redis = None


# ---------------------------------------------------------------- prefix publication
def prefix_document(db: Session) -> dict:
    rows = db.execute(select(ProtectedPrefix.prefix).where(ProtectedPrefix.enabled)
                      .order_by(ProtectedPrefix.prefix)).scalars().all()
    return {"prefixes": [str(p) for p in rows], "published_at": int(time.time())}


def publish_prefixes(db: Session) -> bool:
    """Tell the collector which prefixes to account. Returns False if Redis is unavailable;
    the periodic republisher in main.py will retry."""
    try:
        rds().set(KEY_PREFIXES, json.dumps(prefix_document(db)))
        return True
    except redis.RedisError as e:
        log.warning("could not publish prefixes to redis: %s", e)
        return False


# ---------------------------------------------------------------- live data
def _get_json(key: str) -> Any | None:
    try:
        raw = rds().get(key)
    except redis.RedisError:
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def live_snapshot() -> dict:
    """Latest per-second snapshot, marked unavailable when missing or stale."""
    s = get_settings()
    snap = _get_json(KEY_LATEST)
    now = time.time()
    if snap is None:
        return {"available": False, "reason": "no live data (collector stopped or Redis unavailable)",
                "ts": None, "in": None, "out": None, "dsts": []}
    age = now - snap.get("ts", 0)
    snap["age_seconds"] = round(age, 1)
    snap["available"] = age <= s.live_stale_seconds + 1  # +1: the bucket closes after its second ends
    if not snap["available"]:
        snap["reason"] = f"latest data is {age:.0f}s old"
        for d in ("in", "out"):
            if snap.get(d):
                snap[d]["provenance"] = "unavailable"
    return snap


def history(seconds: int) -> list[dict]:
    try:
        raw = rds().lrange(KEY_HISTORY, 0, max(0, seconds - 1))
    except redis.RedisError:
        return []
    out = []
    for r in reversed(raw):
        try:
            out.append(json.loads(r))
        except ValueError:
            continue
    return out


def collector_status() -> dict:
    st = _get_json(KEY_COLLECTOR)
    if st is None:
        return {"running": False, "reason": "no status published in the last 15s"}
    st["running"] = True
    st["age_seconds"] = round(time.time() - st.get("ts", 0), 1)
    now = time.time()
    for e in st.get("exporters", []):
        e["stale"] = now - e.get("last_seen", 0) > 60
    return st


def interfaces() -> list[dict]:
    try:
        raw = rds().hgetall(KEY_IFACES)
    except redis.RedisError:
        return []
    s = get_settings()
    now = time.time()
    out = []
    for v in raw.values():
        try:
            r = json.loads(v)
        except ValueError:
            continue
        r["age_seconds"] = round(now - r.get("ts", 0), 1)
        if r["age_seconds"] > s.iface_stale_seconds:
            r["provenance"] = "unavailable"
        out.append(r)
    out.sort(key=lambda r: (r.get("agent", ""), r.get("if_index", 0)))
    return out


def redis_ok() -> bool:
    try:
        return bool(rds().ping())
    except redis.RedisError:
        return False


# ---------------------------------------------------------------- ClickHouse
class ClickHouseUnavailable(RuntimeError):
    pass


def ch_query(sql: str, params: dict[str, Any] | None = None) -> list[dict]:
    """Run a read-only query using ClickHouse server-side parameters ({name:Type} placeholders),
    so user input is never interpolated into SQL."""
    s = get_settings()
    qp: dict[str, Any] = {"default_format": "JSON", "readonly": "1", "max_execution_time": "15",
                          "database": s.clickhouse_database}
    for k, v in (params or {}).items():
        qp[f"param_{k}"] = v
    try:
        r = httpx.post(s.clickhouse_url, params=qp, content=sql.encode(), timeout=20,
                       headers={"X-ClickHouse-User": s.clickhouse_user, "X-ClickHouse-Key": s.clickhouse_password})
    except httpx.HTTPError as e:
        raise ClickHouseUnavailable(str(e)) from e
    if r.status_code != 200:
        raise ClickHouseUnavailable(r.text[:300])
    return r.json().get("data", [])


def clickhouse_ok() -> bool:
    try:
        ch_query("SELECT 1 AS ok")
        return True
    except ClickHouseUnavailable:
        return False


def utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S")
