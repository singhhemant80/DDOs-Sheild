"""Second-by-second scenarios for the detection engine (no database, no Redis)."""
import ipaddress
from dataclasses import replace

import pytest

from app.detector.engine import Baselines, Engine, Profile, ProfileSet, classify, Sample

T0 = 1_800_000_000
V4 = Profile(id=1, name="Default IPv4", scope=ipaddress.ip_network("0.0.0.0/0"))
V6 = Profile(id=2, name="Default IPv6", scope=ipaddress.ip_network("::/0"))


def engine(*extra, overrides=None, baselines=None):
    return Engine(ProfileSet([V4, V6, *extra], overrides), baselines)


def dst(ip, pps, *, proto="udp", syn=0.0, ack=0.0, frag=0.0, reflect=None, size=500, sources=1000,
        prov="sampled", prefix="163.5.191.0/24"):
    d = {"ip": ip, "prefix": prefix, "pps": pps, "bps": pps * size * 8, "tcp_pps": 0.0, "udp_pps": 0.0,
         "icmp_pps": 0.0, "other_pps": 0.0, "syn_pps": syn, "ack_pps": ack, "rst_pps": 0.0, "frag_pps": frag,
         "sources_est": sources, "provenance": prov}
    d[f"{proto}_pps"] = pps
    if reflect:
        d["reflect"] = reflect
    return d


def run(eng, seconds, start, make):
    """Feed `seconds` snapshots; make(i) returns the dst list for second i. Returns all events."""
    evs = []
    for i in range(seconds):
        evs += eng.tick({"ts": start + i, "dsts": make(i)})
    return evs


def kinds(evs, key=None):
    return [e.kind for e in evs if e.kind != "update" and (key is None or e.key == key)]


def first(evs, kind):
    return next(e for e in evs if e.kind == kind)


VICTIM = "163.5.191.20"
VKEY = "163.5.191.20/32"


# ---------------------------------------------------------------- normal traffic
def test_normal_traffic_creates_nothing():
    eng = engine()
    evs = run(eng, 300, T0, lambda i: [dst(VICTIM, 2_000, proto="tcp"), dst("163.5.191.21", 800)])
    assert evs == [] and eng.tracks == {}


# ---------------------------------------------------------------- full attack lifecycle
def test_udp_flood_suspected_confirmed_then_ended():
    eng = engine()
    evs = run(eng, 40, T0, lambda i: [dst(VICTIM, 1_000_000, size=512)])
    sus, conf = first(evs, "suspected"), first(evs, "confirmed")
    assert sus.ts == T0 + 2                     # 3 hot seconds out of 5
    assert conf.ts == T0 + 19                   # needs a full 20 s window, 80% hot, confidence >= 0.7
    assert conf.confidence >= 0.8
    assert conf.vectors[0] == "udp_flood" and "volumetric_pps" in conf.vectors
    assert conf.severity in ("high", "critical")
    assert conf.breakdown["specificity"] == 0.7 and conf.breakdown["baseline_known"] is False

    # Attack stops: released only after 120 consecutive quiet seconds.
    evs = run(eng, 125, T0 + 40, lambda i: [dst(VICTIM, 500)])
    res = first(evs, "resolved")
    assert res.resolution == "ended" and res.ts == T0 + 40 + 119
    assert res.peak_pps == 1_000_000 and res.started_ts == T0 + 2 and res.confirmed_ts == T0 + 19


def test_syn_flood_vector():
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(VICTIM, 800_000, proto="tcp", syn=800_000, size=60)])
    c = first(evs, "confirmed")
    assert c.vectors[0] == "syn_flood" and c.breakdown["specificity"] == 0.9


def test_reflection_is_named_and_not_called_udp_flood():
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(VICTIM, 400_000, reflect={"123": 395_000}, size=468)])
    c = first(evs, "confirmed")
    assert c.vectors[0] == "ntp_amplification" and "udp_flood" not in c.vectors
    assert c.confidence >= 0.9


@pytest.mark.parametrize("port,vector", [("53", "dns_amplification"), ("1900", "ssdp_amplification"),
                                         ("389", "cldap_amplification"), ("11211", "memcached_amplification")])
def test_other_reflection_vectors(port, vector):
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(VICTIM, 100_000, reflect={port: 99_000}, size=1400)])
    assert vector in first(evs, "confirmed").vectors


def test_icmp_and_fragment_floods():
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(VICTIM, 300_000, proto="icmp", size=98),
                                      dst("163.5.191.30", 200_000, frag=200_000, size=1480)])
    assert "icmp_flood" in [v for e in evs if e.kind == "confirmed" and e.key == VKEY for v in e.vectors]
    assert "fragment_flood" in [v for e in evs if e.kind == "confirmed" and e.key == "163.5.191.30/32" for v in e.vectors]


# ---------------------------------------------------------------- false positives
def test_short_spike_never_opens_an_incident():
    eng = engine()
    evs = run(eng, 2, T0, lambda i: [dst(VICTIM, 2_000_000)])
    evs += run(eng, 60, T0 + 2, lambda i: [dst(VICTIM, 1_000)])
    assert kinds(evs) == []


def test_brief_burst_is_suspected_then_cleared_without_confirmation():
    eng = engine()
    evs = run(eng, 5, T0, lambda i: [dst(VICTIM, 2_000_000)])
    evs += run(eng, 70, T0 + 5, lambda i: [dst(VICTIM, 1_000)])
    assert kinds(evs) == ["suspected", "resolved"]
    assert first(evs, "resolved").resolution == "cleared_unconfirmed"


def test_flash_crowd_stays_suspected_and_is_never_confirmed():
    """150k pps of ordinary web traffic from 15k clients: over the volume threshold, but nothing
    attack-shaped. It is visible to operators as suspected and never qualifies for mitigation."""
    eng = engine()
    evs = run(eng, 120, T0, lambda i: [dst(VICTIM, 150_000, proto="tcp", size=900, sources=15_000)])
    assert kinds(evs) == ["suspected"]
    last = [e for e in evs if e.key == VKEY][-1]
    assert last.status == "suspected" and set(last.vectors) == {"volumetric_pps", "volumetric_bps"}
    assert last.current_confidence < 0.7


def test_unknown_sampling_lowers_confidence_below_confirmation():
    eng = engine()
    evs = run(eng, 40, T0, lambda i: [dst(VICTIM, 250_000, prov="estimated"),
                                      dst("163.5.191.21", 250_000, prov="sampled")])
    assert "confirmed" not in kinds(evs, VKEY)
    assert "confirmed" in kinds(evs, "163.5.191.21/32")
    est = [e for e in evs if e.key == VKEY][-1]
    assert est.breakdown["quality"] == 0.7


# ---------------------------------------------------------------- stability
def test_pulsing_attack_does_not_flap():
    eng = engine()
    run(eng, 25, T0, lambda i: [dst(VICTIM, 1_000_000)])
    # 10 s on / 20 s off for 10 minutes: never 120 quiet seconds in a row.
    evs = run(eng, 600, T0 + 25, lambda i: [dst(VICTIM, 1_000_000 if i % 30 < 10 else 0)])
    assert "resolved" not in kinds(evs) and "suspected" not in kinds(evs)


def test_missing_data_never_resolves_an_attack():
    eng = engine()
    run(eng, 25, T0, lambda i: [dst(VICTIM, 1_000_000)])
    # Collector silent for 30 minutes, then one quiet second arrives.
    evs = eng.tick({"ts": T0 + 25 + 1800, "dsts": []})
    assert "resolved" not in kinds(evs)
    assert eng.tracks[VKEY].status == "confirmed" and eng.tracks[VKEY].quiet_seconds == 1


def test_duplicate_and_out_of_order_seconds_are_ignored():
    eng = engine()
    run(eng, 5, T0, lambda i: [dst(VICTIM, 1_000_000)])
    assert eng.tick({"ts": T0 + 2, "dsts": [dst(VICTIM, 1_000_000)]}) == []
    assert len(eng.tracks[VKEY].history) == 5


def test_severity_escalation_event():
    eng = engine()
    evs = run(eng, 10, T0, lambda i: [dst(VICTIM, 150_000, size=100)])
    evs += run(eng, 10, T0 + 10, lambda i: [dst(VICTIM, 5_000_000, size=100)])
    esc = [e for e in evs if e.kind == "escalated"]
    assert esc and esc[-1].severity == "critical" and esc[0].breakdown["previous"] == "low"


# ---------------------------------------------------------------- carpet bombing
def test_carpet_bombing_detected_at_prefix_level_only():
    eng = engine()
    hosts = [f"163.5.191.{i}" for i in range(1, 201)]
    evs = run(eng, 25, T0, lambda i: [dst(h, 5_000, size=500) for h in hosts])
    keys = {e.key for e in evs if e.kind == "confirmed"}
    assert keys == {"163.5.191.0/24"}
    c = first(evs, "confirmed")
    assert c.scope == "prefix" and c.vectors == ["carpet_bombing", "udp_flood"]


def test_single_big_target_is_not_reported_as_carpet_bombing():
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(VICTIM, 900_000)] + [dst(f"163.5.191.{i}", 1_000) for i in range(30, 40)])
    assert {e.key for e in evs if e.kind == "confirmed"} == {VKEY}


def test_several_host_attacks_in_one_prefix_are_not_carpet_bombing():
    eng = engine()
    evs = run(eng, 25, T0, lambda i: [dst(f"163.5.191.{n}", 400_000) for n in (20, 21, 22, 23)])
    assert {e.key for e in evs if e.kind == "confirmed"} == {f"163.5.191.{n}/32" for n in (20, 21, 22, 23)}


# ---------------------------------------------------------------- profiles
def test_most_specific_profile_and_customer_override():
    vps = Profile(id=7, name="VPS block", scope=ipaddress.ip_network("163.5.191.0/24"), dst_pps=50_000, dst_bps=None,
                  udp_pps=None)
    eng = engine(vps, overrides={"163.5.191.99/32": (10_000, None)})
    evs = run(eng, 10, T0, lambda i: [dst("163.5.191.20", 60_000), dst("163.5.191.99", 15_000),
                                      dst("77.107.95.9", 60_000, prefix="77.107.95.0/24")])
    sus = {e.key: e.profile_id for e in evs if e.kind == "suspected"}
    assert sus == {"163.5.191.20/32": 7, "163.5.191.99/32": 7}   # 77.107.95.9 is under the default 100k


def test_disabled_checks_are_skipped():
    p = replace(V4, udp_pps=None, dst_pps=None, dst_bps=None)
    assert classify(Sample(pps=5e6, bps=1e10, udp=5e6), p) == []


# ---------------------------------------------------------------- restart, false positives
def test_restore_after_restart_then_release():
    eng = engine()
    eng.restore(VKEY, "host", "163.5.191.0/24", "confirmed", T0 - 600, T0 - 580, "high", ["udp_flood"], 0.9, 1e6, 4e9)
    evs = run(eng, 121, T0, lambda i: [])
    res = first(evs, "resolved")
    assert res.ts == T0 + 119 and res.vectors == ["udp_flood"] and res.started_ts == T0 - 600


def test_false_positive_suppresses_reopening():
    eng = engine()
    run(eng, 10, T0, lambda i: [dst(VICTIM, 1_000_000)])
    eng.close(VKEY, suppress_until=T0 + 100)
    evs = run(eng, 80, T0 + 10, lambda i: [dst(VICTIM, 1_000_000)])
    assert "suspected" not in kinds(evs)
    evs = run(eng, 10, T0 + 101, lambda i: [dst(VICTIM, 1_000_000)])
    assert "suspected" in kinds(evs)


# ---------------------------------------------------------------- baselines
def test_baseline_learning_and_anomaly_detection():
    bl = Baselines()
    eng = engine(baselines=bl)
    # 35 minutes at ~1000 pps in the same hour of the week (needs 30 samples).
    start = T0 - T0 % 3600
    run(eng, 35 * 60, start, lambda i: [dst(VICTIM, 1_000 + (i % 7) * 10)])
    mean, std = bl.get(VKEY, start + 35 * 60)
    assert 990 < mean < 1_070 and std < 100
    # 30k pps: below every absolute threshold, far above normal -> anomaly, suspected, never confirmed.
    evs = run(eng, 60, start + 35 * 60, lambda i: [dst(VICTIM, 30_000, proto="tcp")])
    assert kinds(evs) == ["suspected"]
    last = [e for e in evs if e.key == VKEY][-1]
    assert last.vectors == ["traffic_anomaly"] and last.severity == "low" and last.breakdown["baseline_known"]


def test_baseline_not_learned_during_an_incident():
    bl = Baselines()
    eng = engine(baselines=bl)
    start = T0 - T0 % 3600
    run(eng, 5 * 60, start, lambda i: [dst(VICTIM, 1_000_000)])
    assert not [k for k in bl.stats if k[0] == VKEY]
