"""Attack sources: top source addresses, AS and countries per incident, stored at close."""
import gzip
import json
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx

from app import asn
from app.db import session_factory
from app.models import AttackIncident, IncidentStatus, Severity
from tests.test_traffic import CH_URL, ch_db, needs_ch  # noqa: F401  (fixture)

ASN_LINES = [
    "198.51.100.0\t198.51.100.255\t64500\tUS\tEXAMPLE-NET-A\n",
    "203.0.113.0\t203.0.113.255\t64501\tNL\tEXAMPLE-NET-B\n",
    "192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n",
    "2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64502\tDE\tEXAMPLE-NET-6\n",
]


def test_asn_table_lookup(tmp_path, monkeypatch):
    p = tmp_path / "ip2asn-combined.tsv.gz"
    with gzip.open(p, "wt") as f:
        f.writelines(ASN_LINES)
    monkeypatch.setattr(asn, "get_settings", lambda: type("S", (), {"asn_db_path": str(p)})())
    monkeypatch.setattr(asn, "_table", None)
    t = asn.table()
    assert t.lookup("198.51.100.77") == asn.AsInfo(64500, "EXAMPLE-NET-A", "US")
    assert t.lookup("2001:db8::9").asn == 64502
    assert t.lookup("::ffff:203.0.113.5").country == "NL"
    nr = t.lookup("192.0.2.1")
    assert nr.asn == 0 and nr.name == "Not routed" and nr.country == ""
    assert t.lookup("8.8.8.8") is None and t.lookup("garbage") is None
    assert asn.status()["loaded"] and asn.status()["ranges"] == 4


def _insert(table: str, rows: list[dict]):
    r = httpx.post(CH_URL, params={"query": f"INSERT INTO shield_test.{table} FORMAT JSONEachRow",
                                   "input_format_skip_unknown_fields": "1"},
                   content="\n".join(json.dumps(x) for x in rows).encode())
    assert r.status_code == 200, r.text


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


@needs_ch
def test_incident_sources_live_then_stored(client, engineer, ch_db, monkeypatch):  # noqa: F811
    monkeypatch.setattr(asn, "table", lambda: asn.parse(ASN_LINES))
    now = time.time()
    start = datetime.fromtimestamp(now - 120, UTC)
    with session_factory()() as db, db.begin():
        inc = AttackIncident(target="163.5.191.20/32", status=IncidentStatus.CONFIRMED, severity=Severity.HIGH,
                             vectors=["ntp_amplification"], confidence=Decimal("0.9"), first_detected_at=start,
                             confirmed_at=start, last_hot_at=start)
        db.add(inc)
        db.flush()
        iid = inc.id
    src, dst, nets = [], [], []
    for w in range(6):  # six 10-second windows
        t = _ts(now - 100 + w * 10)
        nets += [{"ts": t, "dst": "163.5.191.20", "prefix": "163.5.191.0/24", "asn": a, "country": cc, "pps": p,
                  "bps": p * 8000, "sources": n, "dst_pps": 10000.0}
                 for a, cc, p, n in ((64500, "US", 8000.0, 2), (65999, "", 1000.0, 1), (4294967294, "", 900.0, 40))]
        src += [
            {"ts": t, "dst": "163.5.191.20", "prefix": "163.5.191.0/24", "src": "198.51.100.7", "pps": 6000.0,
             "bps": 6e7, "proto": 17, "src_port": 123, "dst_port": 80, "dst_pps": 10000.0, "sources": 3},
            {"ts": t, "dst": "163.5.191.20", "prefix": "163.5.191.0/24", "src": "198.51.100.8", "pps": 2000.0,
             "bps": 2e7, "proto": 17, "src_port": 123, "dst_port": 80, "dst_pps": 10000.0, "sources": 3},
            {"ts": t, "dst": "163.5.191.20", "prefix": "163.5.191.0/24", "src": "203.0.113.9", "src_as": 65999,
             "pps": 1000.0, "bps": 1e7, "proto": 17, "src_port": 123, "dst_port": 80, "dst_pps": 10000.0, "sources": 3},
            # another destination: must not appear
            {"ts": t, "dst": "163.5.191.21", "prefix": "163.5.191.0/24", "src": "8.8.8.8", "pps": 9e9, "bps": 1.0,
             "proto": 6, "src_port": 1, "dst_port": 2, "dst_pps": 9e9, "sources": 1},
        ]
        dst += [{"ts": _ts(now - 100 + w * 10 + s), "dst": "163.5.191.20", "prefix": "163.5.191.0/24",
                 "pps": 10000.0, "bps": 1e8, "provenance": "sampled", "reflect": {}} for s in range(10)]
    _insert("src_10s", src)
    _insert("dst_1s", dst)

    # Without per-network rows (data from before they existed), networks come from listed sources.
    r = client.get(f"/api/v1/attacks/{iid}/sources", headers=engineer).json()
    assert [a["asn"] for a in r["asns"]] == [64500, 65999] and r["networks_cover_all"] is False
    _insert("asn_10s", nets)

    r = client.get(f"/api/v1/attacks/{iid}/sources", headers=engineer).json()
    assert r["available"] and not r["stored"]
    assert [s["ip"] for s in r["sources"]] == ["198.51.100.7", "198.51.100.8", "203.0.113.9"]
    top = r["sources"][0]
    assert top["asn"] == 64500 and top["as_name"] == "EXAMPLE-NET-A" and top["country"] == "US"
    assert top["packets"] == 6000 * 10 * 6 and top["proto"] == "UDP" and top["src_port"] == 123
    # The router's exported AS wins over the table; the name is then not guessed from another AS.
    assert r["sources"][2]["asn"] == 65999 and r["sources"][2]["as_name"] == "AS65999"
    # Per-network totals cover every packet, including the 40 unlisted sources in unknown space.
    assert r["networks_cover_all"] is True
    assert [a["asn"] for a in r["asns"]] == [64500, 65999, None]
    assert r["asns"][0]["as_name"] == "EXAMPLE-NET-A" and r["asns"][1]["as_name"] == "AS65999"
    assert r["asns"][2]["as_name"].startswith("Unknown") and r["asns"][2]["sources"] == 40
    assert abs(r["asns"][0]["share"] - 0.8) < 0.01 and abs(r["asns"][2]["share"] - 0.09) < 0.01
    assert r["total_packets"] == 10000 * 60 and abs(r["listed_share"] - 0.9) < 0.01
    assert r["countries"][0]["country"] == "US" and r["max_sources_per_window"] == 3

    # Closed: the detector stores the summary; the API then serves it even after the data is gone.
    with session_factory()() as db, db.begin():
        db.get(AttackIncident, iid).status = IncidentStatus.RESOLVED
        db.get(AttackIncident, iid).resolved_at = datetime.now(UTC) - timedelta(seconds=40)
    from app.detector.service import DetectorService
    svc = DetectorService.__new__(DetectorService)
    svc.sf = session_factory()
    assert svc._store_sources() == 1
    httpx.post(CH_URL, content=b"TRUNCATE TABLE shield_test.src_10s")
    r = client.get(f"/api/v1/attacks/{iid}/sources", headers=engineer).json()
    assert r["stored"] and r["sources"][0]["ip"] == "198.51.100.7"
    hist = client.get("/api/v1/attacks?state=closed", headers=engineer).json()
    assert hist[0]["top_asns"][0] == {"asn": 64500, "as_name": "EXAMPLE-NET-A", "share": r["asns"][0]["share"]}


def test_sources_reports_clickhouse_down(client, engineer, monkeypatch):
    monkeypatch.setenv("SHIELD_CLICKHOUSE_URL", "http://127.0.0.1:1")
    from app.config import get_settings
    get_settings.cache_clear()
    now = datetime.now(UTC)
    with session_factory()() as db, db.begin():
        inc = AttackIncident(target="163.5.191.22/32", status=IncidentStatus.SUSPECTED, severity=Severity.LOW,
                             vectors=["udp_flood"], confidence=Decimal("0.5"), first_detected_at=now, last_hot_at=now)
        db.add(inc)
        db.flush()
        iid = inc.id
    try:
        r = client.get(f"/api/v1/attacks/{iid}/sources", headers=engineer).json()
        assert r["available"] is False and "ClickHouse" in r["reason"]
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


@needs_ch
def test_old_incident_graph_uses_minute_rollups(client, engineer, ch_db):  # noqa: F811
    t0 = time.time() - 40 * 86400
    start = datetime.fromtimestamp(t0, UTC)
    with session_factory()() as db, db.begin():
        inc = AttackIncident(target="163.5.191.20/32", status=IncidentStatus.RESOLVED, severity=Severity.HIGH,
                             vectors=["udp_flood"], confidence=Decimal("0.9"), first_detected_at=start,
                             confirmed_at=start, last_hot_at=start, resolved_at=start + timedelta(minutes=10))
        db.add(inc)
        db.flush()
        iid = inc.id
    # dst_1s TTL (30 days) would drop these rows; write the rollup directly through its view's source shape.
    rows = []
    for m in range(10):
        ts = _ts(t0 + m * 60)
        rows.append(f"SELECT toDateTime('{ts}', 'UTC') AS ts, '163.5.191.20' AS dst, '163.5.191.0/24' AS prefix, "
                    f"countState(toUInt8(1)) AS seconds, avgState(toFloat64(50000)) AS pps_avg, maxState(toFloat64(60000)) AS pps_max, "
                    f"avgState(toFloat64(4e8)) AS bps_avg, maxState(toFloat64(5e8)) AS bps_max, avgState(toFloat64(49000)) AS udp_avg, "
                    f"avgState(toFloat64(0)) AS syn_avg")
    q = "INSERT INTO shield_test.dst_1m " + " UNION ALL ".join(rows)
    r = httpx.post(CH_URL, content=q.encode())
    assert r.status_code == 200, r.text
    s = client.get(f"/api/v1/attacks/{iid}/series", headers=engineer).json()
    assert s["available"] and s["resolution"] == "1m" and s["step_seconds"] >= 60
    assert s["points"] and max(p["pps"] for p in s["points"]) == 50000
