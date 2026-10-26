"""Detector service against real PostgreSQL + Redis, and the incident API."""
import json
import os
import time

import pytest
import redis
from sqlalchemy import select

from app import telemetry as tm
from app.detector.service import STREAM, DetectorService
from app.models import AttackIncident, AttackIncidentEvent, DetectionEvidence, Role
from tests.conftest import login, make_user

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
try:
    R.ping()
    HAVE_REDIS = True
except redis.RedisError:
    HAVE_REDIS = False
pytestmark = pytest.mark.skipif(not HAVE_REDIS, reason="Redis not available")

VICTIM = "163.5.191.20"
VKEY = "163.5.191.20/32"


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield


@pytest.fixture
def prefix(client, engineer):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24", "description": "VPS"}, headers=engineer)
    client.post("/api/v1/customers/ips", json={"address": VICTIM, "customer_ref": "C-1042",
                                               "customer_name": "Nimbus", "service_type": "vps"}, headers=engineer)
    return r.json()


def flood(ts, pps=1_000_000, **extra):
    d = {"ip": VICTIM, "prefix": "163.5.191.0/24", "pps": pps, "bps": pps * 4096, "udp_pps": pps, "tcp_pps": 0,
         "icmp_pps": 0, "other_pps": 0, "syn_pps": 0, "ack_pps": 0, "rst_pps": 0, "frag_pps": 0,
         "sources_est": 4000, "provenance": "sampled", **extra}
    return {"ts": ts, "dsts": [d] if pps else []}


def feed(svc, start, n, pps=1_000_000):
    for i in range(n):
        svc.process(flood(start + i, pps))
    return start + n


def incident(db):
    db.expire_all()
    return db.execute(select(AttackIncident)).scalars().one()


def timeline(db, iid):
    return [e.kind for e in db.execute(select(AttackIncidentEvent).where(AttackIncidentEvent.incident_id == iid)
                                       .order_by(AttackIncidentEvent.id)).scalars()]


T0 = int(time.time()) - 3600


def test_full_lifecycle_is_persisted_and_published(db, prefix):
    ps = R.pubsub()
    ps.subscribe("shield:events")
    svc = DetectorService(rds=R)
    t = feed(svc, T0, 30)
    inc = incident(db)
    assert inc.status.value == "confirmed" and str(inc.target) == VKEY and inc.scope == "host"
    assert inc.protected_prefix_id == prefix["id"] and inc.vectors[0] == "udp_flood"
    assert inc.peak_pps == 1_000_000 and float(inc.confidence) >= 0.8 and inc.profile_id is not None
    assert timeline(db, inc.id)[:2] == ["suspected", "confirmed"]
    ev = db.execute(select(DetectionEvidence).where(DetectionEvidence.incident_id == inc.id)).scalars().all()
    assert ev and {e.metric for e in ev} >= {"udp_flood"} and ev[0].details["sample"]["pps"] == 1_000_000

    feed(svc, t, 125, pps=0)
    inc = incident(db)
    assert inc.status.value == "resolved" and inc.resolution == "ended" and inc.resolved_at is not None
    assert timeline(db, inc.id)[-1] == "resolved"

    published = []
    while (m := ps.get_message(timeout=0.2)) is not None:
        if m["type"] == "message":
            published.append(json.loads(m["data"])["event"])
    assert {"suspected", "confirmed", "resolved"} <= set(published)


def test_stream_consumption_via_poll(db, prefix):
    svc = DetectorService(rds=R)
    svc.stream_id = "0"
    for i in range(10):
        R.xadd(STREAM, {"d": json.dumps(flood(T0 + i))})
    assert svc.poll_once(block_ms=100) == 10
    assert incident(db).status.value == "suspected"
    assert json.loads(R.get("shield:detector:status"))["processed"] == 10


def test_restart_resumes_open_incident(db, prefix):
    svc = DetectorService(rds=R)
    t = feed(svc, T0, 30)
    svc2 = DetectorService(rds=R)            # simulated restart
    assert svc2.incidents == {VKEY: incident(db).id}
    assert timeline(db, incident(db).id)[-1] == "detector_restarted"
    feed(svc2, t, 121, pps=0)
    inc = incident(db)
    assert inc.status.value == "resolved" and inc.resolution == "ended"


def test_data_gap_holds_incident_open(db, prefix):
    svc = DetectorService(rds=R)
    t = feed(svc, T0, 30)
    svc.last_snapshot_wall -= 30
    svc._check_gap(time.time())
    svc.process(flood(t + 600, 0))
    inc = incident(db)
    assert inc.status.value == "confirmed"
    assert timeline(db, inc.id)[-2:] == ["data_gap", "data_resumed"]


def test_false_positive_closes_and_suppresses(client, as_role, db, prefix):
    svc = DetectorService(rds=R)
    t = feed(svc, T0, 10)
    iid = str(incident(db).id)
    noc = as_role(Role.NOC_OPERATOR)
    r = client.post(f"/api/v1/attacks/{iid}/false-positive", json={"note": "Customer's backup job"}, headers=noc)
    assert r.status_code == 200 and r.json()["status"] == "false_positive"
    svc._sync_external()
    feed(svc, t, 60)
    db.expire_all()
    assert len(db.execute(select(AttackIncident)).scalars().all()) == 1   # not reopened
    assert client.post(f"/api/v1/attacks/{iid}/false-positive", json={"note": "again"}, headers=noc).status_code == 409


def test_incident_api_list_detail_ack_notes(client, as_role, db, prefix):
    svc = DetectorService(rds=R)
    feed(svc, T0, 30)
    ro, noc = as_role(Role.READ_ONLY), as_role(Role.NOC_OPERATOR)
    rows = client.get("/api/v1/attacks", headers=ro).json()
    assert len(rows) == 1 and rows[0]["customer"]["customer_ref"] == "C-1042" and rows[0]["prefix"] == "163.5.191.0/24"
    iid = rows[0]["id"]
    assert client.get("/api/v1/attacks?state=closed", headers=ro).json() == []
    assert client.get("/api/v1/attacks?q=163.5.191.0/24", headers=ro).json()[0]["id"] == iid
    assert client.get("/api/v1/attacks?q=77.107.95.0/24", headers=ro).json() == []
    s = client.get("/api/v1/attacks/summary", headers=ro).json()
    assert s["open"] == 1 and s["confirmed"] == 1 and s["unacknowledged"] == 1

    assert client.post(f"/api/v1/attacks/{iid}/acknowledge", headers=ro).status_code == 403
    r = client.post(f"/api/v1/attacks/{iid}/acknowledge", headers=noc).json()
    assert r["acknowledged_by"].startswith("nocoperator")
    assert client.post(f"/api/v1/attacks/{iid}/notes", json={"note": "Called customer"}, headers=noc).status_code == 204

    d = client.get(f"/api/v1/attacks/{iid}", headers=ro).json()
    kinds = [e["kind"] for e in d["timeline"]]
    assert kinds[:2] == ["suspected", "confirmed"] and "acknowledged" in kinds and kinds[-1] == "note"
    assert d["confidence_breakdown"]["specificity"] == 0.7 and d["evidence"]
    assert d["eligibility"]["protected_prefix"] == "163.5.191.0/24" and d["eligibility"]["rtbh_allowed"] is False
    assert d["profile"]["name"] == "Default IPv4"


def test_profiles_api(client, engineer, as_role):
    lst = client.get("/api/v1/detection/profiles", headers=engineer).json()
    assert [p["scope"] for p in lst] == ["0.0.0.0/0", "::/0"] and all(p["is_default"] for p in lst)
    body = {**{k: v for k, v in lst[0].items() if k not in ("id", "is_default", "updated_at")},
            "name": "VPS block", "scope": "163.5.191.0/24", "dst_pps": 50_000}
    r = client.post("/api/v1/detection/profiles", json=body, headers=engineer)
    assert r.status_code == 201
    pid = r.json()["id"]
    assert client.post("/api/v1/detection/profiles", json={**body, "name": "dup"}, headers=engineer).status_code == 409
    assert client.post("/api/v1/detection/profiles", json={**body, "name": "x", "scope": "10.0.0.0/8",
                                                         "suspect_hits": 9, "suspect_window": 5},
                       headers=engineer).status_code == 422
    assert client.delete(f"/api/v1/detection/profiles/{lst[0]['id']}", headers=engineer).status_code == 409
    d = {**body, "name": lst[0]["name"], "scope": "0.0.0.0/0", "enabled": False}
    assert client.put(f"/api/v1/detection/profiles/{lst[0]['id']}", json=d, headers=engineer).status_code == 422
    noc = as_role(Role.NOC_OPERATOR)
    assert client.post("/api/v1/detection/profiles", json={**body, "name": "n", "scope": "77.107.95.0/24"},
                       headers=noc).status_code == 403
    assert client.delete(f"/api/v1/detection/profiles/{pid}", headers=engineer).status_code == 204


def test_profile_change_reaches_running_detector(client, engineer, db, prefix):
    svc = DetectorService(rds=R)
    lst = client.get("/api/v1/detection/profiles", headers=engineer).json()
    body = {**{k: v for k, v in lst[0].items() if k not in ("id", "is_default", "updated_at")},
            "name": "VPS block", "scope": "163.5.191.0/24", "dst_pps": 10_000, "udp_pps": 10_000}
    assert client.post("/api/v1/detection/profiles", json=body, headers=engineer).status_code == 201
    svc._reload_profiles()
    feed(svc, T0, 5, pps=20_000)          # below the 100k default, above the new 10k
    assert incident(db).status.value == "suspected"


def test_detector_status_and_health(client, engineer):
    assert client.get("/api/v1/detection/status", headers=engineer).json()["running"] is False
    svc = DetectorService(rds=R)
    svc._publish_status()
    assert client.get("/api/v1/detection/status", headers=engineer).json()["running"] is True
    assert client.get("/api/v1/health/details", headers=engineer).json()["components"]["detector"] in ("up", "degraded")


def test_websocket_forwards_incident_events(client):
    make_user("watcher", Role.READ_ONLY)
    tok = login(client, "watcher")["access_token"]
    with client.websocket_connect("/api/v1/ws/traffic") as ws:
        ws.send_json({"token": tok})
        assert ws.receive_json()["type"] == "ready"
        got = None
        deadline = time.time() + 5
        while got is None and time.time() < deadline:
            R.publish("shield:events", json.dumps({"type": "incident", "event": "confirmed", "incident": {"id": "x"}}))
            m = ws.receive_json()
            if m.get("type") == "incident":
                got = m
        assert got["event"] == "confirmed"
