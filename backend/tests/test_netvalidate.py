import pytest

from app import netvalidate as nv


@pytest.mark.parametrize("p", ["163.5.191.0/24", "77.107.95.0/24", "163.52.252.0/23", "2a0f:1234::/32"])
def test_valid_public_prefixes(p):
    assert str(nv.validate_public_prefix(p)) == p


@pytest.mark.parametrize("p,msg", [
    ("163.5.191.5/24", "host bits"),
    ("10.0.0.0/8", "bogon"),
    ("192.168.1.0/24", "bogon"),
    ("100.64.0.0/16", "bogon"),
    ("203.0.113.0/24", "bogon"),
    ("8.0.0.0/7", "/8"),
    ("not-a-prefix", "invalid"),
])
def test_rejected_prefixes(p, msg):
    with pytest.raises(ValueError) as e:
        nv.validate_public_prefix(p)
    assert msg in str(e.value).lower() or msg in str(e.value)


def test_lab_ranges_allowed_when_requested():
    assert str(nv.validate_public_prefix("192.0.2.0/24", allow_lab_ranges=True)) == "192.0.2.0/24"


def test_target_parsing():
    assert str(nv.parse_target("163.5.191.20")) == "163.5.191.20/32"
    assert str(nv.parse_target("2a0f::1")) == "2a0f::1/128"


@pytest.mark.parametrize("raw,norm", [
    ("174:666", "174:666"), ("blackhole", "65535:666"), (" 65535:666 ", "65535:666"),
    ("154950:666:0", "154950:666:0"),
])
def test_communities(raw, norm):
    assert nv.normalise_community(raw) == norm


@pytest.mark.parametrize("bad", ["154950:666", "abc", "1:2:3:4", "70000:1"])
def test_bad_communities(bad):
    with pytest.raises(ValueError):
        nv.normalise_community(bad)


@pytest.mark.parametrize("asn,ok", [(154950, True), (174, True), (0, False), (23456, False), (64500, False),
                                    (4294967295, False)])
def test_asn(asn, ok):
    if ok:
        assert nv.validate_asn(asn) == asn
    else:
        with pytest.raises(ValueError):
            nv.validate_asn(asn)
