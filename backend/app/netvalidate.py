"""Network value validation shared by API and (later) mitigator."""
from __future__ import annotations

import ipaddress
import re

# Ranges that must never be configured as protected (public) address space.
_BOGONS_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)]
_BOGONS_V6 = [ipaddress.ip_network(n) for n in (
    "::/8", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)]

_COMMUNITY = re.compile(r"^(\d{1,10}):(\d{1,10})$")
_LARGE_COMMUNITY = re.compile(r"^(\d{1,10}):(\d{1,10}):(\d{1,10})$")
_WELL_KNOWN = {"blackhole": "65535:666", "no-export": "65535:65281", "no-advertise": "65535:65282"}


def parse_prefix(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Strict: host bits must be zero (163.5.191.5/24 is rejected, not silently masked)."""
    try:
        return ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as e:
        raise ValueError(f"invalid prefix {value!r}: {e}") from None


def parse_target(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """A bare address becomes a host route (/32 or /128)."""
    v = value.strip()
    if "/" not in v:
        addr = ipaddress.ip_address(v)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}")
    return parse_prefix(v)


def bogon_overlap(net) -> str | None:
    for b in (_BOGONS_V4 if net.version == 4 else _BOGONS_V6):
        if net.overlaps(b):
            return str(b)
    return None


def validate_public_prefix(value: str, *, allow_lab_ranges: bool = False):
    net = parse_prefix(value)
    if net.version == 4 and not 8 <= net.prefixlen <= 32:
        raise ValueError("IPv4 protected prefix length must be between /8 and /32")
    if net.version == 6 and not 16 <= net.prefixlen <= 128:
        raise ValueError("IPv6 protected prefix length must be between /16 and /128")
    if not allow_lab_ranges:
        b = bogon_overlap(net)
        if b:
            raise ValueError(f"{net} overlaps reserved/bogon range {b}")
    return net


def normalise_community(value: str) -> str:
    v = value.strip().lower()
    v = _WELL_KNOWN.get(v, v)
    m = _COMMUNITY.match(v)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > 65535 or b > 65535:
            raise ValueError(f"standard community {value!r} out of range (each half 0-65535)")
        return f"{a}:{b}"
    m = _LARGE_COMMUNITY.match(v)
    if m:
        parts = [int(x) for x in m.groups()]
        if any(p > 4294967295 for p in parts):
            raise ValueError(f"large community {value!r} out of range")
        return ":".join(map(str, parts))
    raise ValueError(f"invalid BGP community {value!r} (expected A:B or A:B:C)")


def validate_asn(asn: int) -> int:
    if not 1 <= asn <= 4294967295:
        raise ValueError("ASN must be between 1 and 4294967295")
    if asn in (23456,) or 64496 <= asn <= 64511 or 65535 <= asn <= 65551 or asn == 4294967295:
        raise ValueError(f"AS{asn} is reserved/documentation-only")
    return asn
