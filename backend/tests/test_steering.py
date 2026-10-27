"""Phase 9 part 2: selective upstream steering through the router's BGP output filters."""
import hashlib
import os
import time
import uuid
from datetime import UTC, datetime

import pytest
import redis
from sqlalchemy import select, text

from app import telemetry as tm
from app.db import session_factory
from app.mikrotik.api import WriteRefused, colon_fingerprint
from app.mikrotik.filterapi import check_filter_write
from app.mikrotik.simulator import RouterOSSimulator
from app.mitigation import steering as stg
from app.mitigation.controller import Controller
from app.mitigation.speaker import SimulatedSpeaker
from app.models import ActionState, AuditLog, FilterRule, MitigationAction, RouterState

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
API = "/api/v1/mitigation"
VICTIM = "163.5.191.20"
P = "163.5.191.0/24"
EVIDENCE = {"ownership_verified": True, "ownership_evidence": "RIPE route object"}
FW_USER, FW_PW = "shield-fw", "Filter-Password-123"


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield
    R.flushdb()


def _state(rid: int, bgp: list[dict], routes=(P,)):
    with session_factory()() as db, db.begin():
        db.merge(RouterState(router_id=rid, polled_at=datetime.now(UTC), ok=True, bgp=bgp,
                             routes={"items": [{"dst": r, "gateway": "sfp-sfpplus3"} for r in routes]}))


@pytest.fixture
def lab(client, engineer):
    assert client.post("/api/v1/prefixes", json={"prefix": P, "rtbh_allowed": True, "steering_allowed": True, **EVIDENCE},
                       headers=engineer).status_code == 201
    rid = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "10.255.0.1"},
                      headers=engineer).json()["id"]
    a = client.post("/api/v1/upstreams", json={"name": "Cyfuture", "asn": 174, "router_id": rid, "capacity_mbps": 10000},
                    headers=engineer).json()["id"]
    b = client.post("/api/v1/upstreams", json={"name": "Protected", "asn": 6939, "router_id": rid, "capacity_mbps": 10000,
                                               "ddos_protected": True}, headers=engineer).json()["id"]
    _state(rid, [{"name": "upstream-a", "remote_as": "174", "output_filter": "upstream-a-out", "remote_address": "198.51.100.1"},
                 {"name": "upstream-b", "remote_as": "6939", "output_filter": "upstream-b-out", "remote_address": "203.0.113.1"}])
    return {"router": rid, "a": a, "b": b}


def preview(client, h, **body):
    return client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "steering", **body}, headers=h).json()


def propose(client, h, **body):
    return client.post(f"{API}/actions", json={"target": VICTIM, "strategy": "steering", **body},
                       headers={**h, "Idempotency-Key": uuid.uuid4().hex})


def run(c, n=3):
    for _ in range(n):
        c.next_try.clear()
        c.tick()


def actions():
    with session_factory()() as db:
        return db.execute(select(MitigationAction).order_by(MitigationAction.created_at)).scalars().all()


U = "shield:7741c48a-7255-430d-bd65-e91c05ac2fa3:0"


def test_guard_allows_only_shield_steering_rules():
    add = ["/routing/filter/rule/add", "=chain=shield-steer-3", f"=comment={U}"]
    for rule in ("if (dst == 163.5.191.0/24) { reject; }", "if (dst == 163.5.191.0/24) { set bgp-path-prepend 3; }",
                 "if (dst == 163.5.191.0/24) { append bgp-communities 174:990; }"):
        check_filter_write(add + [f"=rule={rule}"], {})
    check_filter_write(["/routing/filter/rule/add", "=chain=upstream-a-out", "=rule=jump shield-steer-3",
                        "=comment=shield:steer-jump:3", "=place-before=*1"], {})
    for bad in (
        add + ["=rule=if (dst == 163.5.191.0/24) { accept; }"],                   # accept skips the operator's rules
        add + ["=rule=if (dst in 0.0.0.0/0) { reject; }"],                        # everything
        add + ["=rule=if (dst == 163.5.191.20/32) { reject; }"],                  # not an announced prefix
        add + ["=rule=reject;"],
        add + ["=rule=if (dst == 163.5.191.0/24) { reject; }; jump other"],
        ["/routing/filter/rule/add", "=chain=upstream-a-out", "=rule=if (dst == 163.5.191.0/24) { reject; }", f"=comment={U}"],
        ["/routing/filter/rule/add", "=chain=upstream-a-out", "=rule=jump shield-steer-4", "=comment=shield:steer-jump:3"],
        ["/routing/filter/rule/remove", "=numbers=*1"],
        ["/routing/bgp/connection/set", "=numbers=*1", "=disabled=yes"],
    ):
        with pytest.raises(WriteRefused):
            check_filter_write(bad, {})


def test_plan_suggests_moving_to_protected_upstream(client, engineer, lab):
    p = preview(client, engineer)
    assert not p["blocked"], [c for c in p["checks"] if c["level"] == "block"]
    assert p["target"] == P                       # the /24 holding the address
    assert [r["upstream"] for r in p["routes"]] == ["Cyfuture"]
    assert p["routes"][0]["steering"][0]["mode"] == "withhold" and p["routes"][0]["steering"][0]["out_chain"] == "upstream-a-out"
    assert any("arrive only over Protected" in s for s in p["impact"]["statements"])
    assert any("256 addresses" in s for s in p["impact"]["statements"])


def test_plan_refuses_unreachable_and_checks_router(client, engineer, lab):
    both = [{"upstream_id": lab["a"], "mode": "withhold"}, {"upstream_id": lab["b"], "mode": "withhold"}]
    p = preview(client, engineer, steering=both)
    assert p["blocked"] and any(c["code"] == "steer_unreachable" for c in p["checks"])
    # Prepend and provider communities are fine together with a withhold elsewhere.
    p = preview(client, engineer, steering=[{"upstream_id": lab["a"], "mode": "prepend", "prepend": 3},
                                            {"upstream_id": lab["b"], "mode": "communities", "communities": ["6939:666"]}])
    assert not p["blocked"] and {r["steering"][0]["mode"] for r in p["routes"]} == {"prepend", "communities"}
    # No output chain on the session: blocked. No exact route: warning.
    _state(lab["router"], [{"name": "upstream-a", "remote_as": "174", "output_filter": None},
                           {"name": "upstream-b", "remote_as": "6939", "output_filter": "upstream-b-out"}], routes=())
    p = preview(client, engineer, steering=[{"upstream_id": lab["a"], "mode": "withhold"}])
    assert p["blocked"] and any("no output filter chain" in c["message"] for c in p["checks"])
    p = preview(client, engineer, steering=[{"upstream_id": lab["b"], "mode": "prepend", "prepend": 2}])
    assert any(c["code"].endswith("_announced") for c in p["checks"])


def test_plan_needs_steering_allowed(client, engineer, lab):
    pid = client.get("/api/v1/prefixes", headers=engineer).json()[0]["id"]
    client.patch(f"/api/v1/prefixes/{pid}", json={"steering_allowed": False}, headers=engineer)
    p = preview(client, engineer)
    assert p["blocked"] and any(c["code"] == "steering_not_allowed" for c in p["checks"])


def test_simulated_steering_end_to_end(client, engineer, lab):
    r = propose(client, engineer)
    assert r.status_code == 201, r.text
    aid = r.json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ACTIVE and str(a.target) == P and a.upstream_id == lab["a"], a.error
    t = stg.SimulatedSteering(R)
    from app.mitigation.filtering import RouterTarget
    rt = RouterTarget(lab["router"], "edge-r1", "", 0, True, True, None, None, None)
    rules = t.rules(rt)
    assert list(rules) == [f"shield:{aid}:0"] and rules[f"shield:{aid}:0"]["row"]["rule"] == f"if (dst == {P}) {{ reject; }}"
    assert SimulatedSpeaker(R).routes() == {}        # nothing announced, nothing blackholed
    # A second action that withholds from the remaining upstream would leave the prefix unannounced.
    p = preview(client, engineer, steering=[{"upstream_id": lab["b"], "mode": "withhold"}])
    assert p["blocked"] and any(c["code"] == "steer_unreachable" for c in p["checks"])
    client.post(f"{API}/actions/{aid}/withdraw", json={"reason": "attack over"}, headers=engineer)
    run(c)
    assert actions()[0].state == ActionState.WITHDRAWN and t.rules(rt) == {}
    with session_factory()() as db:
        assert {x.kind for x in db.execute(select(FilterRule)).scalars()} == {"steer"}


# ---------------------------------------------------------------- RouterOS protocol simulator
@pytest.fixture
def sim():
    s = RouterOSSimulator(tls=True, users={"shield-ro": "Test-Password-123", FW_USER: FW_PW}, writers={FW_USER}).start()
    s.state["/routing/filter/rule"] += [
        {".id": "*11", "chain": "upstream-b-out", "rule": "if (dst in 163.5.191.0/24 && dst-len == 24) { accept; }",
         "comment": "announce our /24 to B", "disabled": "false"},
        {".id": "*12", "chain": "upstream-b-out", "rule": "reject;", "comment": "", "disabled": "false"}]
    yield s
    s.stop()


@pytest.fixture
def ros(client, engineer, admin, sim):
    assert client.post("/api/v1/prefixes", json={"prefix": P, "rtbh_allowed": True, "steering_allowed": True, **EVIDENCE},
                       headers=engineer).status_code == 201
    fp = colon_fingerprint(hashlib.sha256(sim.cert_der).hexdigest())
    rid = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "127.0.0.1",
                                               "api_port": sim.port, "api_username": "shield-ro",
                                               "api_password": "Test-Password-123", "tls_fingerprint": fp},
                      headers=engineer).json()["id"]
    assert client.patch(f"/api/v1/routers/{rid}", json={"filter_username": FW_USER, "filter_password": FW_PW},
                        headers=engineer).status_code == 200
    a = client.post("/api/v1/upstreams", json={"name": "Cyfuture", "asn": 174, "router_id": rid, "capacity_mbps": 10000},
                    headers=engineer).json()["id"]
    b = client.post("/api/v1/upstreams", json={"name": "Protected", "asn": 6939, "router_id": rid, "capacity_mbps": 10000,
                                               "ddos_protected": True}, headers=engineer).json()["id"]
    _state(rid, [{"name": "upstream-a", "remote_as": "174", "output_filter": "upstream-a-out"},
                 {"name": "upstream-b", "remote_as": "6939", "output_filter": "upstream-b-out"}])
    assert client.put("/api/v1/settings/steering_backend", json={"value": "routeros"}, headers=admin).status_code == 200
    return {"router": rid, "a": a, "b": b}


def _rules(sim):
    return sim.state["/routing/filter/rule"]


def test_routeros_steering_end_to_end(client, engineer, ros, sim):
    operator = [dict(r) for r in _rules(sim)]
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ACTIVE, a.error
    rules = _rules(sim)
    chain = f"shield-steer-{ros['a']}"
    mine = [r for r in rules if r["chain"] == chain]
    assert [r["rule"] for r in mine] == [f"if (dst == {P}) {{ reject; }}"] and mine[0]["comment"] == f"shield:{aid}:0"
    out_a = [r for r in rules if r["chain"] == "upstream-a-out"]
    assert out_a[0]["rule"] == f"jump {chain}" and out_a[0]["comment"] == f"shield:steer-jump:{ros['a']}"
    assert [r for r in rules if not (r.get("comment") or "").startswith("shield:")] == operator
    assert not [r for r in rules if r["chain"] == "upstream-b-out" and r.get("comment", "").startswith("shield:")]
    writes = {w[0] for w in sim.commands if w[0] != "/login" and not w[0].endswith("/print")}
    assert writes == {"/routing/filter/rule/add"}, writes

    # Reconcile restores a deleted rule and removes an orphan; operator rules are never touched.
    sim.state["/routing/filter/rule"] = [r for r in rules if r.get("comment") != f"shield:{aid}:0"]
    orphan = f"shield:{uuid.uuid4()}:0"
    sim.state["/routing/filter/rule"].append({".id": "*F9", "chain": chain, "rule": "if (dst == 163.5.191.0/24) { reject; }",
                                              "comment": orphan, "disabled": "false"})
    res = c.reconcile_steering()
    assert res["ok"] and len(res["readded"]) == 1 and len(res["removed"]) == 1, res
    assert f"shield:{aid}:0" in [r.get("comment") for r in _rules(sim)] and orphan not in [r.get("comment") for r in _rules(sim)]

    # Withdraw: the rule and the now-unneeded jump go; the router is as before.
    client.post(f"{API}/actions/{aid}/withdraw", json={"reason": "attack over"}, headers=engineer)
    run(c)
    assert actions()[0].state == ActionState.WITHDRAWN
    assert [r for r in _rules(sim)] == operator
    with session_factory()() as db:
        acts = {x.action for x in db.execute(select(AuditLog)).scalars()}
    assert {"mitigation.steer_add", "mitigation.steer_remove", "mitigation.steer_reconcile"} <= acts


def test_routeros_refuses_empty_output_chain(client, engineer, ros, sim):
    sim.state["/routing/filter/rule"] = [r for r in _rules(sim) if r["chain"] != "upstream-a-out"]
    aid = propose(client, engineer).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    run(c)
    a = actions()[0]
    assert a.state in (ActionState.FAILED, ActionState.ROLLED_BACK) and "has no rules" in (a.error or ""), a.error
    run(c)
    assert actions()[0].state == ActionState.ROLLED_BACK
    assert not [r for r in _rules(sim) if (r.get("comment") or "").startswith("shield:")]


def test_backend_switch_refused_with_open_steering(client, engineer, admin, lab):
    assert propose(client, engineer).status_code == 201
    assert client.put("/api/v1/settings/steering_backend", json={"value": "routeros"}, headers=admin).status_code == 409
