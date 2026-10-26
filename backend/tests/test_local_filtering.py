"""Phase 9 local filtering: narrow drop rules on the router instead of blackholing the address.

Runs the whole workflow against the simulated backend and against the RouterOS protocol
simulator (real API wire protocol, TLS with a pinned certificate, a write-restricted account)."""
import hashlib
import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest
import redis
from sqlalchemy import select, text

from app import security
from app import telemetry as tm
from app.db import session_factory
from app.mikrotik.api import WriteRefused, colon_fingerprint
from app.mikrotik.filterapi import FilterClient, check_filter_write
from app.mikrotik.simulator import RouterOSSimulator
from app.mitigation import filtering as flt
from app.mitigation.controller import Controller
from app.mitigation.speaker import SimulatedSpeaker
from app.models import (
    ActionState, AttackIncident, AuditLog, FilterRule, IncidentStatus, MitigationAction, Router, Severity,
)

R = redis.Redis.from_url(os.environ["SHIELD_REDIS_URL"], decode_responses=True)
API = "/api/v1/mitigation"
VICTIM = "163.5.191.20"
EVIDENCE = {"ownership_verified": True, "ownership_evidence": "RIPE route object"}
FW_USER, FW_PW = "shield-fw", "Filter-Password-123"


@pytest.fixture(autouse=True)
def _flush():
    tm.reset_clients()
    R.flushdb()
    yield
    R.flushdb()


@pytest.fixture
def prefix(client, engineer):
    r = client.post("/api/v1/prefixes", json={"prefix": "163.5.191.0/24", "rtbh_allowed": True, "filtering_allowed": True,
                                              **EVIDENCE}, headers=engineer)
    assert r.status_code == 201, r.text
    return r.json()


def _router(name="edge-r1", addr="10.255.0.1", **kw) -> int:
    with session_factory()() as db, db.begin():
        r = Router(name=name, model="ccr2004", mgmt_address=addr, enabled=True, **kw)
        db.add(r)
        db.flush()
        return r.id


def _incident(vectors=("ntp_amplification",), bps=4e8, target=VICTIM) -> str:
    now = datetime.now(UTC)
    with session_factory()() as db, db.begin():
        inc = AttackIncident(target=f"{target}/32", status=IncidentStatus.CONFIRMED, severity=Severity.HIGH,
                             vectors=list(vectors), confidence=Decimal("0.95"), first_detected_at=now, confirmed_at=now,
                             last_hot_at=now, peak_pps=400_000, peak_bps=int(bps))
        db.add(inc)
        db.flush()
        return str(inc.id)


def propose(client, h, **body):
    return client.post(f"{API}/actions", json={"target": VICTIM, "strategy": "local_filter", **body},
                       headers={**h, "Idempotency-Key": uuid.uuid4().hex})


def run(c: Controller, n=3):
    for _ in range(n):
        c.next_try.clear()
        c.tick()


def actions():
    with session_factory()() as db:
        return db.execute(select(MitigationAction).order_by(MitigationAction.created_at)).scalars().all()


def rules(aid=None):
    with session_factory()() as db:
        q = select(FilterRule).order_by(FilterRule.id)
        if aid:
            q = q.where(FilterRule.action_id == aid)
        return db.execute(q).scalars().all()


# ---------------------------------------------------------------- the write guard
OK_COMMENT = "shield:7741c48a-7255-430d-bd65-e91c05ac2fa3:0"


def test_guard_allows_only_shield_rules():
    drop = ["/ip/firewall/raw/add", "=chain=shield-filter", "=action=drop", "=dst-address=163.5.191.20/32",
            "=protocol=udp", "=src-port=123", f"=comment={OK_COMMENT}"]
    check_filter_write(drop, set())
    check_filter_write(["/ip/firewall/raw/add", "=chain=prerouting", "=action=jump", "=jump-target=shield-filter",
                        "=comment=shield:jump", "=place-before=*1"], set())
    check_filter_write(["/ip/firewall/raw/print", "=stats="], set())
    refused = [
        ["/ip/firewall/filter/add", "=chain=input", "=action=drop", f"=comment={OK_COMMENT}"],    # other table
        ["/ip/firewall/raw/set", "=numbers=*1", "=disabled=yes"],                                 # edit
        ["/ip/firewall/raw/remove", "=numbers=*1"],                                               # not owned
        ["/system/reboot"], ["/user/add", "=name=x"], ["/ip/route/add", "=dst-address=0.0.0.0/0"],
        [w if not w.startswith("=comment") else "=comment=operator rule" for w in drop],           # no shield comment
        [w for w in drop if not w.startswith(("=protocol", "=src-port"))],                         # drops everything
        [w.replace("=action=drop", "=action=accept") for w in drop],                               # accept punches holes
        [w.replace("/32", "/16").replace("163.5.191.20", "163.5.0.0") for w in drop],              # too broad
        [w.replace("=chain=shield-filter", "=chain=prerouting") for w in drop],                    # outside our chain
        drop + ["=src-address-list=x"],                                                            # unknown matcher
        drop[:-1] + [f"=comment={OK_COMMENT}\n/system/reboot"],                                   # injection
        ["/ipv6/firewall/raw/add"] + drop[1:],                                                     # wrong family
    ]
    for w in refused:
        with pytest.raises(WriteRefused):
            check_filter_write(w, set())
    check_filter_write(["/ip/firewall/raw/remove", "=numbers=*1F"], {"*1F"})


def test_derive_rules_from_attack_types():
    m, why = flt.derive(["ntp_amplification", "dns_amplification", "volumetric_bps"], VICTIM)
    assert [(x.protocol, x.src_port) for x in m] == [("udp", 123), ("udp", 53)] and m[0].dst == f"{VICTIM}/32"
    assert why and "bandwidth" in why[0]
    m, why = flt.derive(["syn_flood"], VICTIM)
    assert m == [] and "SYN" in why[0]
    m, _ = flt.derive(["fragment_flood", "icmp_flood"], VICTIM)
    assert {(x.protocol, x.fragment) for x in m} == {(None, True), ("icmp", False)}
    with pytest.raises(ValueError):
        flt.validate({"protocol": "tcp"}, VICTIM)          # all TCP: refused
    with pytest.raises(ValueError):
        flt.validate({}, VICTIM)                           # everything: a blackhole
    assert flt.validate({"protocol": "udp", "dst_port": "27015"}, VICTIM).dst_port == 27015


# ---------------------------------------------------------------- planning
def test_plan_checks(client, engineer, prefix):
    _router()
    inc = _incident()
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "local_filter", "incident_id": inc},
                    headers=engineer).json()
    assert not p["blocked"], p["checks"]
    r = p["routes"][0]
    assert r["router"] == "edge-r1" and r["filters"][0]["src_port"] == 123
    assert "drop UDP packets from port 123 to 163.5.191.20/32" in r["description"]
    assert any(c["code"] == "filter_simulated" for c in p["checks"])
    assert any("All other traffic" in s for s in p["impact"]["statements"])
    # SYN flood: nothing to filter.
    p = client.post(f"{API}/preview", json={"target": "163.5.191.21", "strategy": "local_filter",
                                            "incident_id": _incident(["syn_flood"], target="163.5.191.21")},
                    headers=engineer).json()
    assert p["blocked"] and any(c["code"] == "not_filterable" for c in p["checks"])
    # Link saturation: an upstream of 1 Gb/s and a 4 Gb/s attack.
    client.post("/api/v1/upstreams", json={"name": "Small", "asn": 64600, "capacity_mbps": 1000}, headers=engineer)
    p = client.post(f"{API}/preview", json={"target": "163.5.191.22", "strategy": "local_filter",
                                            "incident_id": _incident(bps=4e9, target="163.5.191.22")},
                    headers=engineer).json()
    assert any(c["code"] == "link_saturated" and c["level"] == "warn" for c in p["checks"])
    # Filtering not allowed on the prefix.
    client.patch(f"/api/v1/prefixes/{prefix['id']}", json={"filtering_allowed": False}, headers=engineer)
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "local_filter", "incident_id": inc},
                    headers=engineer).json()
    assert p["blocked"] and any(c["code"] == "filtering_not_allowed" for c in p["checks"])


def test_routeros_backend_needs_filter_account(client, engineer, admin, prefix):
    _router()
    assert client.put("/api/v1/settings/filter_backend", json={"value": "routeros"}, headers=admin).status_code == 200
    p = client.post(f"{API}/preview", json={"target": VICTIM, "strategy": "local_filter",
                                            "filters": [{"protocol": "udp", "src_port": 123}]}, headers=engineer).json()
    assert p["blocked"] and any("no filter account" in c["message"] for c in p["checks"])
    assert client.put("/api/v1/settings/filter_backend", json={"value": "nonsense"}, headers=admin).status_code == 422


# ---------------------------------------------------------------- simulated end to end
def test_simulated_filter_end_to_end(client, engineer, prefix):
    rid = _router()
    r = propose(client, engineer, incident_id=_incident(), router_ids=[rid])
    assert r.status_code == 201, r.text
    aid = r.json()["actions"][0]["id"]
    assert client.post(f"{API}/actions/{aid}/approve", headers=engineer).status_code == 200
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ACTIVE and a.router_id == rid, a.error
    fr = rules()
    assert [x.status for x in fr] == ["active"] and fr[0].comment == f"shield:{aid}:0" and fr[0].backend == "simulated"
    t = flt.RouterTarget(rid, "edge-r1", "", 0, True, True, None, None, None)
    assert list(flt.SimulatedFilters(R).rules(t)) == [fr[0].comment]
    # Not a blackhole: nothing on the BGP speaker.
    assert SimulatedSpeaker(R).routes() == {}
    d = client.get(f"{API}/actions/{aid}", headers=engineer).json()
    assert d["filters"][0]["description"].startswith("UDP packets from port 123") and d["router"] == "edge-r1"
    assert client.get(f"{API}/filters", headers=engineer).json()["rules"][0]["status"] == "active"
    # Withdraw removes the rule.
    assert client.post(f"{API}/actions/{aid}/withdraw", json={"reason": "attack over"}, headers=engineer).status_code == 200
    run(c)
    assert actions()[0].state == ActionState.WITHDRAWN
    assert [x.status for x in rules()] == ["removed"] and flt.SimulatedFilters(R).rules(t) == {}


def test_simulated_fault_fails_and_rolls_back(client, engineer, prefix):
    rid = _router()
    aid = propose(client, engineer, filters=[{"protocol": "udp", "src_port": 123}], router_ids=[rid]).json()["actions"][0]["id"]
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET timeout_seconds = 1 WHERE id = :i"), {"i": aid})
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    R.set(flt.KEY_FAULT, "filter")
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    import time
    run(c)
    time.sleep(1.1)
    run(c)
    assert actions()[0].state in (ActionState.FAILED, ActionState.ROLLED_BACK)
    R.delete(flt.KEY_FAULT)
    run(c)
    assert actions()[0].state == ActionState.ROLLED_BACK


# ---------------------------------------------------------------- real RouterOS protocol
@pytest.fixture
def sim():
    s = RouterOSSimulator(tls=True, users={"shield-ro": "Test-Password-123", FW_USER: FW_PW}, writers={FW_USER}).start()
    yield s
    s.stop()


def _ros_router(client, engineer, sim) -> int:
    fp = colon_fingerprint(hashlib.sha256(sim.cert_der).hexdigest())
    rid = client.post("/api/v1/routers", json={"name": "edge-r1", "model": "ccr2004", "mgmt_address": "127.0.0.1",
                                               "api_port": sim.port, "api_username": "shield-ro",
                                               "api_password": "Test-Password-123", "tls_fingerprint": fp},
                      headers=engineer).json()["id"]
    # The filter account must differ from the polling one.
    r = client.patch(f"/api/v1/routers/{rid}", json={"filter_username": "shield-ro", "filter_password": "x"}, headers=engineer)
    assert r.status_code == 422
    r = client.patch(f"/api/v1/routers/{rid}", json={"filter_username": FW_USER, "filter_password": FW_PW}, headers=engineer)
    assert r.status_code == 200 and r.json()["access_mode"] == "read_write" and r.json()["has_filter_password"], r.text
    return rid


def test_routeros_filter_end_to_end(client, engineer, admin, prefix, sim):
    rid = _ros_router(client, engineer, sim)
    t = client.post(f"/api/v1/routers/{rid}/filter-test", headers=engineer).json()
    assert t["ok"] and t["group"] == "shield-filter", t
    assert client.put("/api/v1/settings/filter_backend", json={"value": "routeros"}, headers=admin).status_code == 200
    operator_rules = [dict(r) for r in sim.state["/ip/firewall/raw"]]
    aid = propose(client, engineer, incident_id=_incident(["ntp_amplification", "fragment_flood"]),
                  router_ids=[rid]).json()["actions"][0]["id"]
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ACTIVE, a.error
    raw = sim.state["/ip/firewall/raw"]
    # The jump is first, the operator's rules follow unchanged, Shield's drops are in its own chain.
    assert raw[0]["comment"] == "shield:jump" and raw[0]["chain"] == "prerouting" and raw[0]["jump-target"] == "shield-filter"
    assert [r for r in raw if not r["comment"].startswith("shield:")] == operator_rules
    mine = [r for r in raw if r["comment"].startswith(f"shield:{aid}")]
    assert {(r.get("protocol"), r.get("src-port"), r.get("fragment")) for r in mine} == {("udp", "123", None), (None, None, "yes")}
    assert all(r["chain"] == "shield-filter" and r["action"] == "drop" and r["dst-address"] == f"{VICTIM}/32" for r in mine)
    # Every command Shield's filter account sent was a print, an add of its own rule, or nothing else.
    writes = {w[0] for w in sim.commands if w[0] != "/login" and not w[0].endswith("/print")}
    assert writes == {"/ip/firewall/raw/add"}, writes

    # Counters reach the ledger on reconcile.
    sim.count_packets("/ip/firewall/raw", f"shield:{aid}:0", 123456, 70_000_000)
    c.reconcile()
    fr = {x.comment: x for x in rules(aid)}
    assert fr[f"shield:{aid}:0"].packets == 123456

    # Someone deletes Shield's rule on the router: reconcile puts it back. An orphan Shield rule is removed.
    # An operator rule that merely looks similar is never touched.
    sim.state["/ip/firewall/raw"] = [r for r in raw if r["comment"] != f"shield:{aid}:1"]
    orphan = f"shield:{uuid.uuid4()}:0"
    sim.state["/ip/firewall/raw"] += [
        {".id": "*F1", "chain": "shield-filter", "action": "drop", "dst-address": "163.5.191.99/32", "protocol": "udp",
         "comment": orphan, "disabled": "false", "packets": "0", "bytes": "0"},
        {".id": "*F2", "chain": "prerouting", "action": "drop", "protocol": "udp", "comment": "shields up (operator)",
         "disabled": "false", "packets": "0", "bytes": "0"}]
    res = c.reconcile_filters()
    assert res["ok"] and len(res["readded"]) == 1 and len(res["removed"]) == 1, res
    comments = [r["comment"] for r in sim.state["/ip/firewall/raw"]]
    assert f"shield:{aid}:1" in comments and orphan not in comments and "shields up (operator)" in comments

    # Withdraw: Shield's drops go, everything else stays.
    client.post(f"{API}/actions/{aid}/withdraw", json={"reason": "attack over"}, headers=engineer)
    run(c)
    assert actions()[0].state == ActionState.WITHDRAWN
    left = [r["comment"] for r in sim.state["/ip/firewall/raw"]]
    assert not [x for x in left if x.startswith(f"shield:{aid}")]
    assert "management" in left and "operator bogon filter" in left and "shields up (operator)" in left
    with session_factory()() as db:
        acts = {a.action for a in db.execute(select(AuditLog)).scalars()}
    assert {"mitigation.filter_add", "mitigation.filter_remove", "mitigation.filter_reconcile"} <= acts


def test_routeros_account_without_write_fails_cleanly(client, engineer, admin, prefix, sim):
    rid = _ros_router(client, engineer, sim)
    sim.writers.clear()     # the router refuses the account's writes
    client.put("/api/v1/settings/filter_backend", json={"value": "routeros"}, headers=admin)
    aid = propose(client, engineer, filters=[{"protocol": "udp", "src_port": 123}], router_ids=[rid]).json()["actions"][0]["id"]
    with session_factory()() as db, db.begin():
        db.execute(text("UPDATE mitigation_actions SET timeout_seconds = 1 WHERE id = :i"), {"i": aid})
    client.post(f"{API}/actions/{aid}/approve", headers=engineer)
    c = Controller(rds=R, speaker=SimulatedSpeaker(R))
    import time
    run(c, 1)
    time.sleep(1.1)
    run(c)
    a = actions()[0]
    assert a.state == ActionState.ROLLED_BACK and "permissions" in (a.error or ""), a.error
    assert [r["comment"] for r in sim.state["/ip/firewall/raw"]] == ["management", "operator bogon filter"]


def test_filter_client_never_removes_operator_rules(sim):
    c = FilterClient("127.0.0.1", sim.port, FW_USER, FW_PW, use_tls=True, verify_tls=False).connect()
    try:
        c.shield_rules(4)
        with pytest.raises(WriteRefused):
            c.remove(4, "*1")          # the operator's "management" rule
        assert len(sim.state["/ip/firewall/raw"]) == 2
    finally:
        c.close()


def test_backend_switch_refused_with_open_filters(client, engineer, admin, prefix):
    _router()
    aid = propose(client, engineer, filters=[{"protocol": "udp", "src_port": 123}]).json()["actions"][0]["id"]
    assert aid
    r = client.put("/api/v1/settings/filter_backend", json={"value": "routeros"}, headers=admin)
    assert r.status_code == 409


def test_secrets_never_returned(client, engineer, sim):
    rid = _ros_router(client, engineer, sim)
    body = client.get(f"/api/v1/routers/{rid}", headers=engineer).text
    assert FW_PW not in body and '"filter_password"' not in body and 'filter_password_enc' not in body
    with session_factory()() as db:
        assert security.decrypt_secret(db.get(Router, rid).filter_password_enc) == FW_PW
