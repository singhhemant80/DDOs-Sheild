"""Mitigation workflow (simulation): plans and safety checks, idempotent proposals, approvals,
the controller's execute/verify/rollback, withdrawal, expiry, policies and restart reconciliation."""
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import redis
from sqlalchemy import select, text

from app import telemetry as tm
from app.db import session_factory
from app.mitigation.controller import Controller
from app.mitigation.speaker import KEY_FAULT, KEY_RIB, Route, SimulatedSpeaker, SpeakerError
from app.models import (
    ActionState, AttackIncident, AttackIncidentEvent, AuditLog, IncidentStatus, MitigationAction, RtbhRoute,
    RtbhStatus, Role, Severity,
)

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
try:
    R.ping()
    HAVE_REDIS = True
except redis.RedisError:
    HAVE_REDIS = False
pytestmark = pytest.mark.skipif(not HAVE_REDIS, reason="Redis not available")

EVIDENCE = {"ownership_verified": True, "ownership_evidence": "RIPE route object; ROA valid"}
VICTIM = "163.5.191.20"
API = "/api/v1/mitigation"


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield
    R.flushdb()


def _upstream(client, h, name, asn, **policy):
    uid = client.post("/api/v1/upstreams", json={"name": name, "asn": asn, "capacity_mbps": 10000}, headers=h).json()["id"]
    base = f"/api/v1/upstreams/{uid}/rtbh-policy"
    r = client.put(base, json={"communities": [f"{asn}:666"], "documentation_ref": f"https://{name}/rtbh", **policy}, headers=h)
    assert r.status_code == 200, r.text
    assert client.post(f"{base}/verify", headers=h).status_code == 200
    assert client.post(f"{base}/enable", headers=h).status_code == 200
    return uid


@pytest.fixture
def net(client, engineer):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24", "rtbh_allowed": True, **EVIDENCE}, headers=engineer)
    assert r.status_code == 201, r.text
    a = _upstream(client, engineer, "Upstream-A", 174)
    b = _upstream(client, engineer, "Upstream-B", 6939, max_routes=1)
    client.post("/api/v1/customers/ips", json={"address": VICTIM, "customer_ref": "C-1042", "customer_name": "Nimbus",
                                               "service_type": "vps"}, headers=engineer)
    return {"a": a, "b": b}


@pytest.fixture
def noc(as_role):
    return as_role(Role.NOC_OPERATOR)


def ctl():
    return Controller(rds=R, speaker=SimulatedSpeaker(R))


def propose(client, h, target=VICTIM, key=None, **kw):
    return client.post(f"{API}/actions", json={"target": target, **kw},
                       headers={**h, "Idempotency-Key": key or uuid.uuid4().hex})


def actions(state=None):
    with session_factory()() as db:
        q = select(MitigationAction).order_by(MitigationAction.created_at)
        return db.execute(q).scalars().all() if state is None else \
            db.execute(q.where(MitigationAction.state == state)).scalars().all()


def rib():
    return SimulatedSpeaker(R).routes()


def setting(client, admin_h, key, value):
    assert client.put(f"/api/v1/settings/{key}", json={"value": value}, headers=admin_h).status_code == 200


def run_until_active(client, h, approver=None, **kw):
    r = propose(client, h, **kw)
    assert r.status_code == 201, r.text
    aid = r.json()["actions"][0]["id"]
    assert client.post(f"{API}/actions/{aid}/approve", headers=approver or h).status_code == 200
    c = ctl()
    c.tick(force_reconcile=True)
    return r.json(), c


# ---------------------------------------------------------------- plans
def test_preview_shows_routes_checks_and_impact_and_changes_nothing(client, noc, net):
    p = client.post(f"{API}/preview", json={"target": VICTIM}, headers=noc).json()
    assert not p["blocked"] and p["simulation"] and p["target"] == "163.5.191.20/32"
    assert [(r["upstream"], r["communities"], r["no_export"]) for r in p["routes"]] == [
        ("Upstream-A", ["174:666"], True), ("Upstream-B", ["6939:666"], True)]
    assert "announce 163.5.191.20/32 to Upstream-A (AS174)" in p["routes"][0]["description"]
    text_ = " ".join(p["impact"]["statements"])
    assert "legitimate traffic included" in text_ and "No other address in 163.5.191.0/24" in text_
    assert "C-1042" in text_
    assert p["impact"]["live"]["available"] is False          # no collector in tests: said, not guessed
    assert actions() == [] and rib() == {}


def test_partial_upstream_coverage_is_warned(client, noc, net):
    p = client.post(f"{API}/preview", json={"target": VICTIM, "upstream_ids": [net["a"]]}, headers=noc).json()
    assert not p["blocked"]
    w = {c["code"]: c for c in p["checks"]}
    assert w["partial_coverage"]["level"] == "warn" and "Upstream-B" in w["partial_coverage"]["message"]


@pytest.mark.parametrize("target,code", [
    ("198.51.100.7", "not_protected"),
    ("163.5.191.0/24", "scope"),
    ("not-an-ip", "target_invalid"),
])
def test_unsafe_targets_blocked(client, noc, net, target, code):
    p = client.post(f"{API}/preview", json={"target": target}, headers=noc).json()
    assert p["blocked"] and code in {c["code"] for c in p["checks"] if c["level"] == "block"}


def test_own_infrastructure_never_blackholed(client, noc, engineer, net):
    client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "163.5.191.1"}, headers=engineer)
    p = client.post(f"{API}/preview", json={"target": "163.5.191.1"}, headers=noc).json()
    assert p["blocked"] and "own_infrastructure" in {c["code"] for c in p["checks"]}


def test_emergency_stop_and_opt_out_block(client, noc, admin, engineer, net):
    client.post("/api/v1/customers/ips", json={"address": "163.5.191.30", "customer_ref": "C-7", "service_type": "vps",
                                               "rtbh_opt_out": True}, headers=engineer)
    p = client.post(f"{API}/preview", json={"target": "163.5.191.30"}, headers=noc).json()
    assert "customer_opt_out" in {c["code"] for c in p["checks"] if c["level"] == "block"}
    client.post("/api/v1/system/emergency-stop", headers=noc)
    p = client.post(f"{API}/preview", json={"target": VICTIM}, headers=noc).json()
    assert p["blocked"] and "emergency_stop" in {c["code"] for c in p["checks"]}


def test_limits(client, noc, admin, net):
    # Upstream-B allows one route.
    run_until_active(client, noc, target=VICTIM)
    p = client.post(f"{API}/preview", json={"target": "163.5.191.21"}, headers=noc).json()
    assert "upstream_limit" in {c["code"] for c in p["checks"]}
    p = client.post(f"{API}/preview", json={"target": "163.5.191.21", "upstream_ids": [net["a"]]}, headers=noc).json()
    assert not p["blocked"]
    setting(client, admin, "global_max_rtbh_routes", 2)
    p = client.post(f"{API}/preview", json={"target": "163.5.191.21", "upstream_ids": [net["a"]]}, headers=noc).json()
    assert "global_limit" in {c["code"] for c in p["checks"]}


# ---------------------------------------------------------------- proposals
def test_idempotency_key(client, noc, net):
    r1 = propose(client, noc, key="retry-key-0001")
    r2 = propose(client, noc, key="retry-key-0001")
    assert r1.status_code == 201 and r2.status_code == 200 and r2.json()["replayed"]
    assert [a["id"] for a in r1.json()["actions"]] == [a["id"] for a in r2.json()["actions"]]
    assert len(actions()) == 2
    r3 = propose(client, noc, key="retry-key-0001", upstream_ids=[net["a"]])
    assert r3.status_code == 409 and "different request" in r3.json()["detail"]["message"]
    assert client.post(f"{API}/actions", json={"target": VICTIM}, headers=noc).status_code == 422  # no key


def test_blocked_and_duplicate_proposals_refused(client, noc, net):
    r = propose(client, noc, target="163.5.191.0/24")
    assert r.status_code == 409 and any(c["code"] == "scope" for c in r.json()["detail"]["checks"])
    assert propose(client, noc).status_code == 201
    r = propose(client, noc)
    assert r.status_code == 409 and any(c["code"] == "duplicate" for c in r.json()["detail"]["checks"])


def test_read_only_cannot_propose_or_approve(client, as_role, noc, net):
    viewer = as_role(Role.READ_ONLY)
    assert client.post(f"{API}/preview", json={"target": VICTIM}, headers=viewer).status_code == 403
    assert propose(client, viewer).status_code == 403
    aid = propose(client, noc).json()["actions"][0]["id"]
    assert client.post(f"{API}/actions/{aid}/approve", headers=viewer).status_code == 403
    assert client.get(f"{API}/actions", headers=viewer).status_code == 200


# ---------------------------------------------------------------- execute
def test_full_workflow_announces_verifies_and_withdraws(client, noc, net):
    body, _ = run_until_active(client, noc)
    acts = actions()
    assert [a.state for a in acts] == [ActionState.ACTIVE, ActionState.ACTIVE]
    routes = rib()
    assert set(routes) == {f"upstream:{net['a']}|163.5.191.20/32", f"upstream:{net['b']}|163.5.191.20/32"}
    assert routes[f"upstream:{net['a']}|163.5.191.20/32"].communities == ("174:666",)
    with session_factory()() as db:
        rr = db.execute(select(RtbhRoute)).scalars().all()
        assert {r.status for r in rr} == {RtbhStatus.VERIFIED} and all(r.speaker == "simulated" for r in rr)
    d = client.get(f"{API}/actions/{acts[0].id}", headers=noc).json()
    assert [e["detail"]["kind"] for e in d["events"] if e["action_id"] == str(acts[0].id)] == [
        "proposed", "approved", "executing", "active"]
    assert d["expires_at"] and len(d["group"]) == 2

    aid = str(acts[0].id)
    r = client.post(f"{API}/actions/{aid}/withdraw?whole_group=true", json={"reason": "attack over"}, headers=noc)
    assert r.status_code == 200 and {a["state"] for a in r.json()} == {"withdrawing"}
    ctl().tick()
    assert {a.state for a in actions()} == {ActionState.WITHDRAWN} and rib() == {}
    with session_factory()() as db:
        assert {r.status for r in db.execute(select(RtbhRoute)).scalars()} == {RtbhStatus.WITHDRAWN}
        acts = {a.action for a in db.execute(select(AuditLog)).scalars()}
        assert {"mitigation.propose", "mitigation.approve", "mitigation.announce", "mitigation.withdraw"} <= acts
    # Re-blackholing soon after is allowed for a person, with a warning.
    p = client.post(f"{API}/preview", json={"target": VICTIM}, headers=noc).json()
    assert not p["blocked"] and {c["code"]: c["level"] for c in p["checks"]}["flap"] == "warn"


def test_four_eyes_and_mfa(client, noc, as_role, admin, net):
    setting(client, admin, "four_eyes_approval", True)
    aid = propose(client, noc).json()["actions"][0]["id"]
    r = client.post(f"{API}/actions/{aid}/approve", headers=noc)
    assert r.status_code == 409 and "someone other" in r.json()["detail"]["message"]
    setting(client, admin, "require_mfa_for_mitigation", True)
    other = as_role(Role.NOC_OPERATOR)
    r = client.post(f"{API}/actions/{aid}/approve", headers=other)
    assert r.status_code == 403 and "MFA" in r.json()["detail"]
    setting(client, admin, "require_mfa_for_mitigation", False)
    assert client.post(f"{API}/actions/{aid}/approve", headers=other).status_code == 200


def test_reject(client, noc, net):
    aid = propose(client, noc).json()["actions"][0]["id"]
    assert client.post(f"{API}/actions/{aid}/reject", json={"reason": "not needed"}, headers=noc).status_code == 200
    assert {a.state for a in actions()} == {ActionState.REJECTED}
    ctl().tick()
    assert rib() == {}


def test_emergency_stop_after_approval_blocks_execution(client, noc, net):
    aid = propose(client, noc).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=noc)
    client.post("/api/v1/system/emergency-stop", headers=noc)
    ctl().tick()
    acts = actions()
    assert {a.state for a in acts} == {ActionState.REJECTED} and "emergency stop" in acts[0].rejected_reason.lower()
    assert rib() == {}


@pytest.mark.parametrize("fault", ["announce", "verify"])
def test_speaker_failure_fails_then_rolls_back(client, noc, net, fault):
    R.set(KEY_FAULT, fault)
    aid = propose(client, noc, upstream_ids=[net["a"]]).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=noc)
    c = ctl()
    c.tick()
    a = actions()[0]
    assert a.state == ActionState.EXECUTING and a.attempts == 1 and a.error
    with session_factory()() as db, db.begin():   # pretend the timeout has passed
        db.execute(text("UPDATE mitigation_actions SET started_at = now() - interval '2 minutes'"))
    R.delete(KEY_FAULT)
    c.next_try.clear()
    R.set(KEY_FAULT, fault)
    c.tick()
    assert actions()[0].state == ActionState.FAILED
    R.delete(KEY_FAULT)
    c.next_try.clear()
    c.tick()
    assert actions()[0].state == ActionState.ROLLED_BACK and rib() == {}


def test_rollback_never_removes_another_actions_route(client, noc, net):
    other = Route(peer=f"upstream:{net['a']}", prefix="163.5.191.20/32", communities=("174:666",), action_id="someone-else")
    R.set(KEY_FAULT, "verify")
    aid = propose(client, noc, upstream_ids=[net["a"]]).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=noc)
    c = ctl()
    c.tick()
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET state='failed'"))
    R.delete(KEY_FAULT)
    SimulatedSpeaker(R).announce(other)
    c.next_try.clear()
    c.rollback_failed()
    assert actions()[0].state == ActionState.ROLLED_BACK
    assert rib()[other.key].action_id == "someone-else"


# ---------------------------------------------------------------- restart and reconciliation
class Crash(Exception):
    pass


class CrashingSpeaker(SimulatedSpeaker):
    def __init__(self, rds, after_announce: bool):
        super().__init__(rds)
        self.after = after_announce

    def announce(self, route):
        if self.after:
            super().announce(route)
        raise Crash("process killed")


@pytest.mark.parametrize("after_announce", [False, True])
def test_restart_mid_execution_resumes(client, noc, net, after_announce):
    aid = propose(client, noc, upstream_ids=[net["a"]]).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=noc)
    dying = Controller(rds=R, speaker=CrashingSpeaker(R, after_announce))
    with pytest.raises(Crash):
        dying.execute_one(uuid.UUID(aid))
    assert actions()[0].state == ActionState.EXECUTING          # intent was recorded first
    assert bool(rib()) is after_announce
    ctl().tick(force_reconcile=True)                              # "after restart"
    assert actions()[0].state == ActionState.ACTIVE and len(rib()) == 1


def test_reconcile_reannounces_missing_and_withdraws_orphans(client, noc, net):
    run_until_active(client, noc, upstream_ids=[net["a"]])
    key = next(iter(rib()))
    R.hdel(KEY_RIB, key)                                          # speaker lost the route (e.g. it restarted)
    orphan = Route(peer=f"upstream:{net['a']}", prefix="163.5.191.99/32", action_id=str(uuid.uuid4()))
    SimulatedSpeaker(R).announce(orphan)                          # a route nobody wants any more
    res = ctl().reconcile()
    assert res["reannounced"] == [key] and res["withdrawn"] == [orphan.key]
    assert set(rib()) == {key}
    d = client.get(f"{API}/actions/{actions()[0].id}", headers=noc).json()
    assert "reconciled_reannounced" in [e["detail"]["kind"] for e in d["events"]]


def test_speaker_down_is_reported_not_guessed(client, noc, net):
    R.set(KEY_FAULT, "down")
    res = ctl().reconcile()
    assert res["ok"] is False and "unreachable" in res["error"]
    with pytest.raises(SpeakerError):
        SimulatedSpeaker(R).routes()


# ---------------------------------------------------------------- timers
def test_expiry_withdraws_when_quiet_and_extends_while_hot(client, noc, net):
    with session_factory()() as db, db.begin():
        inc = AttackIncident(target=f"{VICTIM}/32", status=IncidentStatus.CONFIRMED, severity=Severity.HIGH,
                             vectors=["udp_flood"], confidence=Decimal("0.95"), first_detected_at=datetime.now(UTC),
                             confirmed_at=datetime.now(UTC), last_hot_at=datetime.now(UTC))
        db.add(inc)
    run_until_active(client, noc, upstream_ids=[net["a"]], incident_id=str(inc.id))
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET expires_at = now() - interval '1 second'"))
    c = ctl()
    c.tick()
    a = actions()[0]
    assert a.state == ActionState.ACTIVE and a.extensions == 1 and a.expires_at > datetime.now(UTC)
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET expires_at = now() - interval '1 second'"))
        db.execute(text("UPDATE attack_incidents SET status='resolved', resolved_at=now()"))
    c.tick()
    c.tick()
    assert actions()[0].state == ActionState.WITHDRAWN and rib() == {}
    with session_factory()() as db:
        kinds = [e.kind for e in db.execute(select(AttackIncidentEvent).order_by(AttackIncidentEvent.id)).scalars()]
    assert "mitigation_active" in kinds and "mitigation_withdrawn" in kinds


def test_unapproved_proposals_expire(client, noc, net):
    propose(client, noc)
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET created_at = now() - interval '1 hour'"))
    ctl().tick()
    a = actions()
    assert {x.state for x in a} == {ActionState.REJECTED} and a[0].rejected_reason.startswith("expired")


# ---------------------------------------------------------------- policies
def _incident(confirmed_ago=120, **kw):
    with session_factory()() as db, db.begin():
        t = datetime.now(UTC) - timedelta(seconds=confirmed_ago)
        inc = AttackIncident(target=f"{VICTIM}/32", status=IncidentStatus.CONFIRMED, severity=Severity.HIGH,
                             vectors=["ntp_amplification"], confidence=Decimal("0.96"), first_detected_at=t,
                             confirmed_at=t, last_hot_at=datetime.now(UTC), peak_pps=900_000, **kw)
        db.add(inc)
    return inc


def _policy(client, h, **kw):
    body = {"name": "VPS amplification", "enabled": True, "scope": "163.5.191.0/24", "vectors": ["ntp_amplification"],
            "min_confidence": 0.9, "min_duration_seconds": 60, "allowed_strategies": ["rtbh_upstream"], **kw}
    r = client.post(f"{API}/policies", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_policy_proposes_for_approval(client, engineer, net):
    _policy(client, engineer)
    inc = _incident()
    ctl().tick(force_reconcile=True)
    a = actions()
    assert len(a) == 2 and {x.state for x in a} == {ActionState.PROPOSED} and a[0].automatic
    assert str(a[0].incident_id) == str(inc.id)
    ctl().tick(force_reconcile=True)
    assert len(actions()) == 2                                    # idempotent: no second proposal


def test_policy_without_approval_needs_automation_switch(client, engineer, admin, net):
    _policy(client, engineer, requires_approval=False)
    inc = _incident()
    ctl().tick(force_reconcile=True)
    assert actions() == []
    with session_factory()() as db:
        ev = db.execute(select(AttackIncidentEvent).where(AttackIncidentEvent.incident_id == inc.id)).scalars().all()
    assert [e.kind for e in ev] == ["mitigation_blocked"] and "turned off" in " ".join(ev[0].detail["reasons"])
    client.post("/api/v1/system/automation?enabled=true", headers=engineer)
    c = ctl()
    c.tick(force_reconcile=True)
    c.tick()
    assert {x.state for x in actions()} == {ActionState.ACTIVE} and len(rib()) == 2


def test_policy_does_not_fire_too_early_or_for_other_vectors(client, engineer, net):
    _policy(client, engineer, min_duration_seconds=600)
    _incident(confirmed_ago=30)
    ctl().tick(force_reconcile=True)
    assert actions() == []


def test_policy_validation_and_permissions(client, engineer, noc, net):
    r = client.post(f"{API}/policies", json={"name": "x", "scope": "163.5.191.0/24", "allowed_strategies": ["teleport"]},
                    headers=engineer)
    assert r.status_code == 422
    r = client.post(f"{API}/policies", json={"name": "x", "scope": "163.5.191.0/24", "vectors": ["made_up"]}, headers=engineer)
    assert r.status_code == 422
    assert client.post(f"{API}/policies", json={"name": "x", "scope": "163.5.191.0/24"}, headers=noc).status_code == 403


def test_live_events_published_after_commit(client, noc, net):
    ps = R.pubsub()
    ps.subscribe("shield:events")
    ps.get_message(timeout=1)
    propose(client, noc, upstream_ids=[net["a"]])
    msgs = []
    for _ in range(10):
        m = ps.get_message(timeout=0.5)
        if m and m["type"] == "message":
            msgs.append(json.loads(m["data"]))
    assert any(m["type"] == "mitigation" and m["event"] == "proposed" for m in msgs)


def test_status_and_routes_endpoints(client, noc, net):
    run_until_active(client, noc, upstream_ids=[net["a"]])
    st = client.get(f"{API}/status", headers=noc).json()
    assert st["mode"] == "simulation" and st["counts"]["active"] == 1 and st["running"]
    r = client.get(f"{API}/routes", headers=noc).json()
    assert r["simulation"] and len(r["ledger"]) == 1 and r["speaker"]["routes"][0]["upstream"] == "Upstream-A"
