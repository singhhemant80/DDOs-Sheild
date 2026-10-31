"""Phase 10: alert channels, delivery, de-duplication, escalation, reports and readiness checks."""
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
import redis
from sqlalchemy import select, text

from app import telemetry as tm
from app.db import session_factory
from app.models import AttackIncident, IncidentStatus, Notification, RouterEvent, Router, Severity
from app.notify import senders
from app.notify.events import Alert, from_event
from app.notify.service import Notifier

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
API = "/api/v1/notifications"


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield
    R.flushdb()


class Hook:
    """A fake HTTP endpoint (webhook / Telegram) recording what it was sent."""

    def __init__(self, status=200):
        self.calls, self.status = [], status

    def transport(self):
        def handle(req: httpx.Request):
            self.calls.append({"url": str(req.url), "headers": dict(req.headers), "body": json.loads(req.content or b"{}")})
            return httpx.Response(self.status, json={"ok": self.status == 200})
        return httpx.MockTransport(handle)


class FakeSMTP:
    sent: list = []

    def __init__(self, cfg):
        self.cfg = cfg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login(self, u, p):
        self.cfg["_login"] = (u, p)

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def _channel(client, admin, **kw):
    body = {"name": "noc-hook", "kind": "webhook", "config": {"url": "https://hooks.example.net/shield"},
            "secret": "signing-key", "min_severity": "medium", **kw}
    r = client.post(f"{API}/channels", json=body, headers=admin)
    assert r.status_code == 201, r.text
    return r.json()


def _incident_msg(event="confirmed", sev="high", iid=None):
    return json.dumps({"type": "incident", "event": event, "incident": {
        "id": iid or str(uuid.uuid4()), "target": "163.5.191.20/32", "severity": sev, "vectors": ["ntp_amplification"],
        "confidence": 0.95, "peak_pps": 400000, "peak_bps": 1.6e9}})


def test_channel_api_validates_and_hides_secrets(client, admin, engineer):
    c = _channel(client, admin, reports="daily")
    assert c["has_secret"] and "signing-key" not in json.dumps(c) and c["reports"] == "daily"
    assert client.post(f"{API}/channels", json={"name": "x", "kind": "email", "config": {"host": "smtp"}}, headers=admin).status_code == 422
    assert client.post(f"{API}/channels", json={"name": "t", "kind": "telegram", "config": {"chat_id": "123"}}, headers=admin).status_code == 422
    assert client.post(f"{API}/channels", json={"name": "y", "kind": "webhook", "config": {"url": "ftp://x"}}, headers=admin).status_code == 422
    assert client.post(f"{API}/channels", json={"name": "z", "kind": "webhook", "config": {"url": "https://a.example"},
                                                "event_types": ["nonsense"]}, headers=admin).status_code == 422
    assert client.post(f"{API}/channels", json={"name": "e", "kind": "webhook", "config": {"url": "https://a.example"}},
                       headers=engineer).status_code == 403
    r = client.patch(f"{API}/channels/{c['id']}", json={"escalate_after_seconds": 600, "reports": "off"}, headers=admin).json()
    assert r["escalate_after_seconds"] == 600 and r["reports"] == "off" and r["config"]["url"].startswith("https://")


def test_event_to_alert_mapping():
    a = from_event(json.loads(_incident_msg()), "https://shield.example.net")[0]
    assert a.type == "incident_confirmed" and a.severity == "high" and "163.5.191.20" in a.title
    assert a.link.startswith("https://shield.example.net/attacks/") and "400 kpps" in a.text()
    m = from_event({"type": "mitigation", "event": "active", "action": {"id": "x", "target": "163.5.191.20/32",
                                                                        "description": "on edge-r1: drop UDP from port 123",
                                                                        "dry_run": True}})[0]
    assert m.type == "mitigation_active" and "(simulation)" in m.title
    assert from_event({"type": "mitigation", "event": "safety_interlock", "detail": {"removed": [{"prefix": "1.2.3.4/32", "name": "lab"}]}})[0].severity == "critical"
    assert from_event({"type": "router_event", "kind": "bgp_down", "router_id": 1, "router": "edge-r1",
                       "message": "BGP session upstream-a down"})[0].type == "bgp_session_down"
    assert from_event({"type": "traffic"}) == []


def test_webhook_delivery_signature_and_dedup(client, admin):
    c = _channel(client, admin)
    hook = Hook()
    n = Notifier(rds=R, transport=hook.transport())
    iid = str(uuid.uuid4())
    assert n.handle_message(_incident_msg(iid=iid)) == 1
    assert n.handle_message(_incident_msg(iid=iid)) == 0        # same event again within the cooldown
    assert n.handle_message(_incident_msg("resolved", "info")) == 0   # below the channel's minimum severity
    assert n.deliver() == 1
    call = hook.calls[0]
    assert call["body"]["type"] == "incident_confirmed" and call["body"]["source"] == "crapplet-shield"
    import hashlib, hmac
    raw = json.dumps(call["body"]).encode()
    assert call["headers"]["x-shield-signature"] == "sha256=" + hmac.new(b"signing-key", raw, hashlib.sha256).hexdigest()
    h = client.get(API, headers=admin).json()
    assert {x["status"] for x in h} == {"sent", "suppressed"} and h[0]["channel"] == "noc-hook"


def test_failed_delivery_retries_then_fails(client, admin):
    _channel(client, admin)
    hook = Hook(status=500)
    clock = [datetime.now(UTC)]
    n = Notifier(rds=R, transport=hook.transport(), clock=lambda: clock[0])
    n.handle_message(_incident_msg())
    for i in range(6):
        n.deliver()
        clock[0] += timedelta(minutes=10)
    with session_factory()() as db:
        row = db.execute(select(Notification)).scalar_one()
    assert row.status == "failed" and row.attempts == 5 and "500" in row.error
    assert len(hook.calls) == 5


def test_telegram_and_email(client, admin):
    tg = client.post(f"{API}/channels", json={"name": "oncall", "kind": "telegram", "config": {"chat_id": "-100123"},
                                              "secret": "123:ABC", "min_severity": "high"}, headers=admin).json()
    em = client.post(f"{API}/channels", json={"name": "mail", "kind": "email", "secret": "smtp-pass", "min_severity": "high",
                                              "config": {"host": "smtp.example.net", "port": 587, "from": "shield@example.net",
                                                         "to": ["noc@example.net"], "username": "shield"}}, headers=admin).json()
    hook = Hook()
    FakeSMTP.sent = []
    n = Notifier(rds=R, transport=hook.transport(), smtp_factory=FakeSMTP)
    n.handle_message(_incident_msg(sev="critical"))
    assert n.deliver() == 2
    assert hook.calls[0]["url"] == "https://api.telegram.org/bot123:ABC/sendMessage"
    assert hook.calls[0]["body"]["chat_id"] == "-100123" and "[CRITICAL]" in hook.calls[0]["body"]["text"]
    assert FakeSMTP.sent[0]["To"] == "noc@example.net" and "Attack on 163.5.191.20" in FakeSMTP.sent[0]["Subject"]
    assert tg["has_secret"] and em["has_secret"]


def test_escalation_once_per_incident(client, admin):
    c = _channel(client, admin, escalate_after_seconds=600)
    now = datetime.now(UTC)
    with session_factory()() as db, db.begin():
        db.add(AttackIncident(target="163.5.191.21/32", status=IncidentStatus.CONFIRMED, severity=Severity.HIGH,
                              vectors=["udp_flood"], confidence=Decimal("0.9"), first_detected_at=now - timedelta(minutes=20),
                              confirmed_at=now - timedelta(minutes=15), last_hot_at=now))
    n = Notifier(rds=R, transport=Hook().transport())
    n.check()
    n.check()
    with session_factory()() as db:
        rows = db.execute(select(Notification).where(Notification.event_type == "incident_unacknowledged")).scalars().all()
    assert len(rows) == 1 and rows[0].severity == Severity.CRITICAL and "not acknowledged for 15 min" in rows[0].payload["title"]


def test_router_events_and_link_saturation(client, admin, engineer):
    _channel(client, admin)
    rid = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "10.255.0.1"},
                      headers=engineer).json()["id"]
    client.post("/api/v1/upstreams", json={"name": "Cyfuture", "asn": 55470, "router_id": rid, "interface_name": "sfp-sfpplus12",
                                           "capacity_mbps": 1000, "saturation_threshold_pct": 85}, headers=engineer)
    n = Notifier(rds=R, transport=Hook().transport())
    n.poll_router_events()          # starts from "now"
    with session_factory()() as db, db.begin():
        db.add(RouterEvent(router_id=rid, at=datetime.now(UTC), kind="bgp_down", severity=Severity.HIGH,
                           message="BGP session upstream-a to 198.51.100.1 went down.", detail={}))
    assert n.poll_router_events() == 1
    R.hset("shield:ifaces", "10.255.0.1|12", json.dumps({"ts": __import__("time").time(), "if_name": "sfp-sfpplus12",
                                                          "in_bps": 9.5e8, "out_bps": 1e8, "agent": "10.255.0.1", "provenance": "measured", "source": "routeros"}))
    assert n.check() == 1
    assert n.check() == 0           # still saturated: not repeated
    with session_factory()() as db:
        types = sorted(x.event_type for x in db.execute(select(Notification)).scalars())
    assert types == ["bgp_session_down", "link_saturated"]


def test_test_message_endpoint(client, admin, monkeypatch):
    c = _channel(client, admin)
    hook = Hook()
    import app.notify.service as svc
    orig = svc.Notifier.__init__
    monkeypatch.setattr(svc.Notifier, "__init__", lambda self, **kw: orig(self, rds=R, transport=hook.transport()))
    r = client.post(f"{API}/channels/{c['id']}/test", headers=admin).json()
    assert r["ok"] and hook.calls[0]["body"]["type"] == "test"


def test_reports_and_csv(client, engineer, admin):
    now = datetime.now(UTC)
    with session_factory()() as db, db.begin():
        for i, (t, bps) in enumerate((("163.5.191.20/32", 2e9), ("163.5.191.20/32", 1e9), ("163.5.191.30/32", 5e8))):
            db.add(AttackIncident(target=t, status=IncidentStatus.RESOLVED, severity=Severity.HIGH, vectors=["ntp_amplification"],
                                  confidence=Decimal("0.9"), first_detected_at=now - timedelta(days=i + 1, minutes=30),
                                  confirmed_at=now - timedelta(days=i + 1, minutes=29), resolved_at=now - timedelta(days=i + 1),
                                  peak_bps=int(bps), peak_pps=100000,
                                  sources_summary={"asns": [{"asn": 64500, "as_name": "EXAMPLE", "packets": 100, "share": 0.8}]}))
    s = client.get("/api/v1/reports/summary?days=7", headers=engineer).json()
    assert s["attacks"] == 3 and s["top_targets"][0] == {"target": "163.5.191.20/32", "attacks": 2, "customer": None}
    assert s["peak"]["bps"] == 2e9 and s["top_source_networks"][0]["asn"] == 64500 and s["total_attack_minutes"] == 90
    r = client.get("/api/v1/reports/incidents.csv?days=7", headers=engineer)
    assert r.status_code == 200 and r.text.count("\n") == 4 and "AS64500 EXAMPLE 80%" in r.text
    from app import reports
    with session_factory()() as db:
        a = reports.as_alert(reports.summary(db, days=7), "report:weekly:x", "https://shield.example.net")
    assert "3 attacks" in a.lines[0] and a.link == "https://shield.example.net/reports"


def test_hardening_checks(client, admin):
    r = client.get("/api/v1/system/hardening", headers=admin).json()
    keys = {c["key"]: c for c in r["checks"]}
    assert keys["admin_mfa"]["level"] == "problem" and keys["alerts"]["level"] == "problem" and not r["ready"]
    assert keys["simulation"]["level"] == "warn"
    _channel(client, admin)
    keys = {c["key"]: c for c in client.get("/api/v1/system/hardening", headers=admin).json()["checks"]}
    assert keys["alerts"]["level"] == "ok" and keys["escalation"]["level"] == "warn"
    assert client.put("/api/v1/settings/dashboard_url", json={"value": "javascript:alert(1)"}, headers=admin).status_code == 422
    assert client.put("/api/v1/settings/dashboard_url", json={"value": "https://shield.example.net"}, headers=admin).status_code == 200
