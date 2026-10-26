API = "/api/v1"


def test_roadmap_reports_phases_and_checklist(client, engineer):
    r = client.get(f"{API}/system/roadmap", headers=engineer).json()
    assert r["current"] == 8 and r["total"] == 10
    st = {p["n"]: p["status"] for p in r["phases"]}
    assert st[8] == "done" and st[9] == "next" and st[10] == "pending"
    keys = {c["key"]: c for c in r["checklist"]}
    assert not keys["prod_switch"]["done"] and keys["prod_switch"]["hint"]
