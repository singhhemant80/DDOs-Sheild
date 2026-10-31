"""Phase 9 part 3: diversion to an on-demand scrubbing provider through its API."""
import json
import os
import uuid

import httpx
import pytest
import redis
from sqlalchemy import select, text

from app import telemetry as tm
from app.db import session_factory
from app.mitigation import scrubbing as scr
from app.mitigation.controller import Controller
from app.mitigation.speaker import SimulatedSpeaker
from app.models import ActionState, AuditLog, MitigationAction

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
API = "/api/v1/mitigation"
VICTIM = "163.5.191.20"
P = "163.5.191.0/24"
EVIDENCE = {"ownership_verified": True, "ownership_evidence": "RIPE route object"}
BASE = "https://8.8.8.8/v1"     # an IP literal: the HTTP transport is mocked, nothing leaves the test
CONFIG = {
    "activate": {"url": BASE + "/divert", "method": "POST", "body": '{"prefix": "{prefix}", "ref": "{action_id}"}'},
    "deactivate": {"url": BASE + "/divert/{prefix}", "method": "DELETE"},
    "status": {"url": BASE + "/divert/{prefix}", "method": "GET", "active_path": "data.state", "active_value": "active"},
}


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield
    R.flushdb()


class FakeProvider:
    """A scrubbing provider's API: records calls, keeps diversions."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict, str]] = []
        self.active: set[str] = set()
        self.fail_activate = False

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append((req.method, str(req.url), dict(req.headers), req.content.decode()))
        if req.headers.get("authorization") != "Bearer s3cret-token":
            return httpx.Response(401, text="bad token")
        path = req.url.path
        if req.method == "POST" and path == "/v1/divert":
            if self.fail_activate:
                return httpx.Response(503, text="busy")
            self.active.add(json.loads(req.content)["prefix"])
            return httpx.Response(202, json={"ok": True})
        pfx = path.removeprefix("/v1/divert/").replace("%2F", "/")
        if req.method == "DELETE":
            self.active.discard(pfx)
            return httpx.Response(200, json={"ok": True})
        if req.method == "GET":
            return httpx.Response(200, json={"data": {"state": "active" if pfx in self.active else "idle"}})
        return httpx.Response(404)


@pytest.fixture
def lab(client, engineer):
    assert client.post("/api/v1/prefixes", json={"prefix": P, "scrubbing_allowed": True, **EVIDENCE},
                       headers=engineer).status_code == 201
    r = client.post("/api/v1/scrubbing/providers", json={
        "name": "CleanPipe", "method": "api", "config": CONFIG, "auth_header": "Authorization",
        "secret": "Bearer s3cret-token", "documentation_ref": "https://cleanpipe.example/docs/api",
        "notes": "clean traffic returns over GRE tunnel gre-clean"}, headers=engineer)
    assert r.status_code == 201, r.text
    assert "s3cret" not in r.text and r.json()["has_secret"]
    pid = r.json()["id"]
    assert client.post(f"/api/v1/scrubbing/providers/{pid}/verify", headers=engineer).status_code == 200
    return {"provider": pid}


def ctl(fake):
    return Controller(rds=R, speaker=SimulatedSpeaker(R), scrubs=scr.HttpScrubbing(transport=httpx.MockTransport(fake)))


def run(c, n=3):
    for _ in range(n):
        c.next_try.clear()
        c.tick()


def actions():
    with session_factory()() as db:
        return db.execute(select(MitigationAction).order_by(MitigationAction.created_at)).scalars().all()


def propose(client, h, **body):
    return client.post(f"{API}/actions", json={"target": VICTIM, "strategy": "scrubbing", **body},
                       headers={**h, "Idempotency-Key": uuid.uuid4().hex})


# ---------------------------------------------------------------- configuration safety
def test_urls_must_be_public_https(monkeypatch):
    monkeypatch.delenv("SHIELD_SCRUBBING_ALLOW_PRIVATE", raising=False)
    for bad in ("http://8.8.8.8/x", "https://127.0.0.1/x", "https://10.1.2.3/x", "https://169.254.169.254/latest",
                "https://[::1]/x", "https://user:pw@8.8.8.8/x", "ftp://8.8.8.8/x", "https://8.8.8.8/{secret}"):
        with pytest.raises(ValueError):
            scr.validate_url(bad)
    assert scr.validate_url("https://8.8.8.8/v1/divert/{prefix}")
    with pytest.raises(ValueError):
        scr.validate_config("api", {"activate": {"url": BASE, "body": "not json {prefix}"}, "deactivate": {"url": BASE}}, resolve=False)
    with pytest.raises(ValueError):
        scr.validate_config("api", {"activate": {"url": BASE, "headers": {"X-A": "a\r\nInjected: 1"}}, "deactivate": {"url": BASE}},
                            resolve=False)


def test_api_refuses_internal_urls_and_hides_token(client, engineer):
    r = client.post("/api/v1/scrubbing/providers", json={"name": "Bad", "config": {
        "activate": {"url": "https://192.168.1.1/x"}, "deactivate": {"url": BASE}}}, headers=engineer)
    assert r.status_code == 422 and "internal" in r.text


def test_change_resets_verification(client, engineer, lab):
    pid = lab["provider"]
    r = client.patch(f"/api/v1/scrubbing/providers/{pid}", json={"secret": "Bearer other"}, headers=engineer)
    assert r.status_code == 200 and r.json()["verified_at"] is None
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "scrubbing", "scrubbing_provider_id": pid},
                    headers=engineer).json()
    assert p["blocked"] and any(c["code"] == "scrub_verified" for c in p["checks"])


# ---------------------------------------------------------------- planning
def test_plan(client, engineer, lab):
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "scrubbing"}, headers=engineer).json()
    assert not p["blocked"], [c for c in p["checks"] if c["level"] == "block"]
    assert p["target"] == P and p["routes"][0]["provider"] == "CleanPipe"
    assert any("GRE" in s for s in p["impact"]["statements"])
    assert any(c["code"] == "scrub_simulated" for c in p["checks"])
    pid = client.get("/api/v1/prefixes", headers=engineer).json()[0]["id"]
    client.patch(f"/api/v1/prefixes/{pid}", json={"scrubbing_allowed": False}, headers=engineer)
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "scrubbing"}, headers=engineer).json()
    assert p["blocked"] and any(c["code"] == "scrubbing_not_allowed" for c in p["checks"])


# ---------------------------------------------------------------- end to end
def test_live_diversion_end_to_end(client, engineer, admin, lab):
    fake = FakeProvider()
    assert client.put("/api/v1/settings/scrubbing_backend", json={"value": "live"}, headers=admin).status_code == 200
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = ctl(fake)
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ACTIVE, a.error
    assert fake.active == {P}
    method, url, headers, body = fake.calls[0]
    assert method == "POST" and json.loads(body) == {"prefix": P, "ref": aid}
    # Provider dropped it: reconcile asks again.
    fake.active.clear()
    res = c.reconcile_scrubbing()
    assert res["renewed"] == [P] and fake.active == {P}
    # Withdraw stops the diversion and checks it is gone.
    client.post(f"{API}/actions/{aid}/withdraw", json={"reason": "attack over"}, headers=engineer)
    run(c)
    assert actions()[0].state == ActionState.WITHDRAWN and fake.active == set()
    assert any(m == "DELETE" for m, *_ in fake.calls)
    with session_factory()() as db:
        acts = {x.action for x in db.execute(select(AuditLog)).scalars()}
        log = json.dumps([x.after for x in db.execute(select(AuditLog)).scalars()], default=str)
    assert {"mitigation.scrub_divert", "mitigation.scrub_stop"} <= acts
    assert "s3cret" not in log


def test_provider_refusal_fails_and_rolls_back(client, engineer, admin, lab):
    fake = FakeProvider()
    client.put("/api/v1/settings/scrubbing_backend", json={"value": "live"}, headers=admin)
    client.patch(f"/api/v1/scrubbing/providers/{lab['provider']}", json={"secret": "Bearer wrong"}, headers=engineer)
    client.post(f"/api/v1/scrubbing/providers/{lab['provider']}/verify", headers=engineer)
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = ctl(fake)
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ROLLED_BACK and "401" in (a.error or ""), (a.state, a.error)


def test_transient_provider_errors_retry(client, engineer, admin, lab):
    fake = FakeProvider()
    fake.fail_activate = True
    client.put("/api/v1/settings/scrubbing_backend", json={"value": "live"}, headers=admin)
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = ctl(fake)
    run(c, 2)
    assert actions()[0].state == ActionState.EXECUTING and actions()[0].attempts >= 1
    fake.fail_activate = False
    run(c)
    assert actions()[0].state == ActionState.ACTIVE


def test_simulated_backend_calls_nothing(client, engineer, lab):
    fake = FakeProvider()
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))   # follows scrubbing_backend = simulated
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    run(c)
    assert actions()[0].state == ActionState.ACTIVE and fake.calls == []
    assert R.hget(scr.KEY_SIM, f"{lab['provider']}|{P}") == aid


def test_manual_provider(client, engineer, lab):
    r = client.post("/api/v1/scrubbing/providers", json={"name": "Phone", "method": "manual",
                                                         "config": {"steps": "Call the NOC on +91 ..."},
                                                         "documentation_ref": "contract section 4"}, headers=engineer)
    pid = r.json()["id"]
    client.post(f"/api/v1/scrubbing/providers/{pid}/verify", headers=engineer)
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "scrubbing", "scrubbing_provider_id": pid},
                    headers=engineer).json()
    assert any(c["code"] == "scrub_manual" for c in p["checks"]) and not p["blocked"]


def test_provider_test_endpoint(client, engineer, lab, monkeypatch):
    fake = FakeProvider()
    real = scr.HttpScrubbing
    monkeypatch.setattr(scr, "HttpScrubbing", lambda: real(transport=httpx.MockTransport(fake)))
    r = client.post(f"/api/v1/scrubbing/providers/{lab['provider']}/test?prefix={P}", headers=engineer).json()
    assert r == {"ok": True, "active": False}
    assert [m for m, *_ in fake.calls] == ["GET"]      # status only: never activates
    with session_factory()() as db:
        db.execute(text("SELECT 1"))
