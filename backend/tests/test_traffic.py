"""Traffic API: prefix publication, live data staleness, interfaces, WebSocket, ClickHouse queries.

Redis tests need SHIELD_TEST_REDIS_URL (default redis://127.0.0.1:6379/15, flushed per test).
ClickHouse tests need SHIELD_TEST_CLICKHOUSE_URL (they create and drop database shield_test).
Both are skipped if the service is unreachable.
"""
import json
import os
import pathlib
import time

import httpx
import pytest
import redis
from starlette.websockets import WebSocketDisconnect

from app import telemetry as tm
from app.models import Role
from tests.conftest import login, make_user

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
try:
    R.ping()
    HAVE_REDIS = True
except redis.RedisError:
    HAVE_REDIS = False

CH_URL = os.environ["SHIELD_CLICKHOUSE_URL"]
try:
    HAVE_CH = httpx.get(CH_URL + "/ping", timeout=1).status_code == 200
except httpx.HTTPError:
    HAVE_CH = False

needs_redis = pytest.mark.skipif(not HAVE_REDIS, reason="Redis not available")
needs_ch = pytest.mark.skipif(not HAVE_CH, reason="ClickHouse not available")


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    if HAVE_REDIS:
        R.flushdb()
    yield


def snap(ts, pps=1000.0, dsts=None):
    return {"ts": ts, "in": {"pps": pps, "bps": pps * 8000, "tcp_pps": 0, "udp_pps": pps, "icmp_pps": 0,
                              "other_pps": 0, "provenance": "sampled"},
            "out": {"pps": 0, "bps": 0, "tcp_pps": 0, "udp_pps": 0, "icmp_pps": 0, "other_pps": 0,
                    "provenance": "unavailable"},
            "dsts": dsts or [], "dst_count": len(dsts or [])}


# ---------------------------------------------------------------- prefix publication
@needs_redis
def test_prefix_changes_are_published_for_the_collector(client, engineer):
    a = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=engineer).json()
    client.post("/api/v1/prefixes", json={"prefix": "77.107.95.0/24"}, headers=engineer)
    doc = json.loads(R.get(tm.KEY_PREFIXES))
    assert doc["prefixes"] == ["77.107.95.0/24", "163.5.191.0/24"]
    client.patch(f"/api/v1/prefixes/{a['id']}", json={"enabled": False}, headers=engineer)
    assert json.loads(R.get(tm.KEY_PREFIXES))["prefixes"] == ["77.107.95.0/24"]


def test_api_still_works_when_redis_is_down(client, engineer, monkeypatch):
    monkeypatch.setenv("SHIELD_REDIS_URL", "redis://127.0.0.1:1/0")
    from app.config import get_settings
    get_settings.cache_clear()
    tm.reset_clients()
    try:
        r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24"}, headers=engineer)
        assert r.status_code == 201  # config changes never depend on Redis
        live = client.get("/api/v1/traffic/live", headers=engineer).json()
        assert live["available"] is False
        assert client.get("/api/v1/health/details", headers=engineer).json()["components"]["redis"] == "down"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
        tm.reset_clients()


# ---------------------------------------------------------------- live data
@needs_redis
def test_live_snapshot_fresh_and_stale(client, engineer):
    assert client.get("/api/v1/traffic/live", headers=engineer).json()["available"] is False
    R.set(tm.KEY_LATEST, json.dumps(snap(int(time.time()) - 1)))
    live = client.get("/api/v1/traffic/live", headers=engineer).json()
    assert live["available"] and live["in"]["provenance"] == "sampled"
    R.set(tm.KEY_LATEST, json.dumps(snap(int(time.time()) - 60)))
    live = client.get("/api/v1/traffic/live", headers=engineer).json()
    assert not live["available"] and live["in"]["provenance"] == "unavailable"


@needs_redis
def test_history_is_chronological(client, engineer):
    now = int(time.time())
    for t in range(now - 5, now):  # collector LPUSHes, newest first
        R.lpush(tm.KEY_HISTORY, json.dumps({"ts": t, "in_pps": t - now}))
    pts = client.get("/api/v1/traffic/history?seconds=10", headers=engineer).json()["points"]
    assert [p["ts"] for p in pts] == list(range(now - 5, now))


@needs_redis
def test_interfaces_matched_to_upstream_and_saturation(client, engineer):
    rid = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "10.255.0.1"},
                      headers=engineer).json()["id"]
    client.post("/api/v1/upstreams", json={"name": "Upstream-A", "asn": 174, "router_id": rid,
                                           "interface_name": "sfp-sfpplus1", "capacity_mbps": 1000,
                                           "saturation_threshold_pct": 85}, headers=engineer)
    now = int(time.time())
    R.hset(tm.KEY_IFACES, "10.255.0.1|3", json.dumps({"agent": "10.255.0.1", "if_index": 3, "if_name": "sfp-sfpplus1",
                                                       "in_bps": 950e6, "out_bps": 1e6, "speed_bps": 10e9, "ts": now,
                                                       "source": "snmp", "provenance": "measured"}))
    R.hset(tm.KEY_IFACES, "10.255.0.9|1", json.dumps({"agent": "10.255.0.9", "if_index": 1, "in_bps": 5,
                                                       "ts": now - 600, "provenance": "measured"}))
    ifs = {i["agent"]: i for i in client.get("/api/v1/traffic/interfaces", headers=engineer).json()["interfaces"]}
    up = ifs["10.255.0.1"]
    assert up["router"] == "edge-r1" and up["upstream"] == "Upstream-A"
    assert up["saturated"] is True and "upstream" in up["advice"] and abs(up["in_util"] - 0.95) < 1e-9
    assert ifs["10.255.0.9"]["provenance"] == "unavailable" and ifs["10.255.0.9"]["router"] is None


@needs_redis
def test_collector_status(client, engineer):
    assert client.get("/api/v1/collector/status", headers=engineer).json()["running"] is False
    R.set(tm.KEY_COLLECTOR, json.dumps({"ts": int(time.time()), "exporters": [
        {"address": "10.255.0.1", "last_seen": int(time.time())}, {"address": "10.255.0.2", "last_seen": 1}]}))
    st = client.get("/api/v1/collector/status", headers=engineer).json()
    assert st["running"] and [e["stale"] for e in st["exporters"]] == [False, True]
    assert client.get("/api/v1/health/details", headers=engineer).json()["components"]["collector"] == "up"


# ---------------------------------------------------------------- WebSocket
def test_websocket_requires_token(client):
    with client.websocket_connect("/api/v1/ws/traffic") as ws:
        ws.send_json({"token": "garbage"})
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_json()
        assert e.value.code == 4401


@needs_redis
def test_websocket_streams_published_snapshots(client):
    make_user("viewer", Role.READ_ONLY)
    tok = login(client, "viewer")["access_token"]
    with client.websocket_connect("/api/v1/ws/traffic") as ws:
        ws.send_json({"token": tok})
        assert ws.receive_json()["type"] == "ready"
        deadline = time.time() + 5
        payload = snap(int(time.time()), 4242.0)
        got = None
        while time.time() < deadline and got is None:
            R.publish(tm.CHAN_TRAFFIC, json.dumps(payload))
            m = ws.receive_json()
            # Pub/sub channels are global across Redis DBs, so ignore any other publisher.
            if m["type"] == "traffic" and m["data"]["in"]["pps"] == 4242.0:
                got = m
        assert got and got["data"]["in"]["pps"] == 4242.0


# ---------------------------------------------------------------- ClickHouse
SCHEMAS = sorted((pathlib.Path(__file__).resolve().parents[2] / "collector" / "clickhouse").glob("[0-9][0-9][0-9]_*.sql"))


def ch(sql: str):
    r = httpx.post(CH_URL, content=sql.encode(), timeout=30)
    assert r.status_code == 200, r.text


@pytest.fixture
def ch_db():
    ch("DROP DATABASE IF EXISTS shield_test SYNC")
    sql = "\n".join(l for f in SCHEMAS for l in f.read_text().splitlines() if not l.strip().startswith("--"))
    sql = sql.replace("shield.", "shield_test.").replace("DATABASE IF NOT EXISTS shield;",
                                                          "DATABASE IF NOT EXISTS shield_test;")
    for stmt in sql.split(";"):
        if stmt.strip():
            ch(stmt.strip())
    yield
    ch("DROP DATABASE IF EXISTS shield_test SYNC")


@needs_ch
def test_destination_series_and_top(client, engineer, ch_db):
    now = int(time.time())
    rows = []
    for i in range(30):
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now - 30 + i))
        rows.append({"ts": t, "dst": "163.5.191.20", "prefix": "163.5.191.0/24", "pps": 1000.0 * (i + 1),
                     "bps": 8e6, "udp_pps": 900.0, "provenance": "sampled", "reflect": {"123": 5.0}})
        rows.append({"ts": t, "dst": "163.5.191.21", "prefix": "163.5.191.0/24", "pps": 10.0, "bps": 1.0,
                     "provenance": "sampled", "reflect": {}})
    body = "\n".join(json.dumps(r) for r in rows)
    r = httpx.post(CH_URL, params={"query": "INSERT INTO shield_test.dst_1s FORMAT JSONEachRow",
                                   "input_format_skip_unknown_fields": "1"}, content=body.encode())
    assert r.status_code == 200, r.text
    s = client.get("/api/v1/traffic/destinations/163.5.191.20?minutes=5", headers=engineer).json()
    assert s["available"] and s["source"] == "dst_1s" and len(s["points"]) == 30
    assert max(p["pps"] for p in s["points"]) == 30000
    # Timestamps must round-trip as UTC whatever the ClickHouse server's time zone is.
    assert abs(s["points"][-1]["t"] - now) <= 5
    top = client.get("/api/v1/traffic/top?minutes=5&limit=1", headers=engineer).json()
    assert top["rows"][0]["dst"] == "163.5.191.20"


@needs_ch
def test_series_rejects_injection(client, engineer, ch_db):
    for bad in ("163.5.191.20' OR 1=1 --", "x", "163.5.191.0/24"):
        assert client.get(f"/api/v1/traffic/destinations/{bad}", headers=engineer).status_code in (404, 422)


def test_clickhouse_down_is_reported_not_raised(client, engineer, monkeypatch):
    monkeypatch.setenv("SHIELD_CLICKHOUSE_URL", "http://127.0.0.1:1")
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        r = client.get("/api/v1/traffic/totals?minutes=60", headers=engineer)
        assert r.status_code == 200 and r.json()["available"] is False
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
