API = "/api/v1"


def test_roadmap_reports_phases_and_checklist(client, engineer):
    r = client.get(f"{API}/system/roadmap", headers=engineer).json()
    assert r["current"] == 8 and r["total"] == 10
    st = {p["n"]: p["status"] for p in r["phases"]}
    assert st[8] == "done" and st[9] == "in_progress" and st[10] == "pending"
    p9 = next(p for p in r["phases"] if p["n"] == 9)
    assert [x["status"] for x in p9["parts"]] == ["done", "pending", "pending"]
    keys = {c["key"]: c for c in r["checklist"]}
    assert not keys["prod_switch"]["done"] and keys["prod_switch"]["hint"]


def test_upstream_add_edit_delete(client, engineer):
    r = client.post(f"{API}/upstreams", json={"name": "Cyfuture", "asn": 55470, "interface_name": "sfp-sfpplus12",
                                              "capacity_mbps": 10000}, headers=engineer)
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    r = client.patch(f"{API}/upstreams/{uid}", json={"capacity_mbps": 20000, "interface_name": "sfp-sfpplus11"}, headers=engineer)
    assert r.status_code == 200 and r.json()["capacity_mbps"] == 20000
    n = client.post(f"{API}/bgp/neighbors", json={"name": "to-cyf", "purpose": "rtbh_upstream", "upstream_id": uid, "local_asn": 65010,
                                                 "remote_asn": 55470, "neighbor_address": "192.0.2.9", "managed_by_shield": True, "max_prefix_out": 5}, headers=engineer)
    assert n.status_code == 201, n.text
    assert client.delete(f"{API}/upstreams/{uid}", headers=engineer).status_code == 409
    assert client.delete(f"{API}/bgp/neighbors/{n.json()['id']}", headers=engineer).status_code == 204
    assert client.delete(f"{API}/upstreams/{uid}", headers=engineer).status_code == 204
