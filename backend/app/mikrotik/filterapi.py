"""RouterOS client for Shield's local filtering (Phase 9), with a hard write allow-list.

The read-only client (api.ReadOnlyClient) can never change a router. This subclass may make
exactly these changes and nothing else, whatever the account's permissions:

  * add a drop rule to /ip(v6)/firewall/raw in chain "shield-filter", with a comment
    "shield:<action id>:<n>", a destination address and protocol/port/fragment matchers;
  * add the single jump rule "shield:jump" (chain prerouting -> shield-filter) at the top;
  * remove a rule by .id, but only an .id this client has itself read from the router in this
    session with a comment starting "shield:".

Every word is validated before anything is sent; anything else raises WriteRefused. Shield never
edits or removes the operator's own rules, and never touches any other part of the configuration.
"""
from __future__ import annotations

import ipaddress
import re

from .api import READ_COMMAND, ReadOnlyClient, WriteRefused, check_read_only

RAW = {4: "/ip/firewall/raw", 6: "/ipv6/firewall/raw"}
ROUTING_RULES = "/routing/filter/rule"
CHAIN = "shield-filter"
JUMP_COMMENT = "shield:jump"
STEER_CHAIN = re.compile(r"^shield-steer-([0-9]{1,6})$")
STEER_JUMP = re.compile(r"^shield:steer-jump:([0-9]{1,6})$")
CHAIN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PFX = r"(?P<pfx>[0-9a-fA-F:.]{2,43}/[0-9]{1,3})"
_COMM = r"[0-9]{1,10}:[0-9]{1,10}(?::[0-9]{1,10})?"
STEER_RULES = [
    re.compile(rf"^if \(dst == {_PFX}\) \{{ reject; \}}$"),
    re.compile(rf"^if \(dst == {_PFX}\) \{{ set bgp-path-prepend [1-5]; \}}$"),
    re.compile(rf"^if \(dst == {_PFX}\) \{{ append bgp-communities {_COMM}(?:,{_COMM}){{0,3}}; \}}$"),
]
COMMENT = re.compile(r"^shield:(?:jump|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9]{1,2})$")
ROS_ID = re.compile(r"^\*[0-9A-Fa-f]{1,8}$")
PROTOCOLS = {"udp", "tcp", "icmp", "icmpv6"}
ADD_ATTRS = {"chain", "action", "jump-target", "dst-address", "protocol", "src-port", "dst-port", "fragment",
             "comment", "place-before", "disabled"}


def _port(v: str) -> bool:
    return v.isdigit() and 1 <= int(v) <= 65535


def _owned(owned, base: str) -> set[str]:
    return owned.get(base, set()) if isinstance(owned, dict) else owned


def check_steer_add(attrs: dict[str, str]) -> None:
    """A routing filter rule Shield may add: its own rule in a shield-steer-<n> chain, or the one
    jump into that chain at the top of an upstream's output chain."""
    if not set(attrs) <= {"chain", "rule", "comment", "place-before", "disabled"}:
        raise WriteRefused(f"argument(s) {sorted(set(attrs) - {'chain', 'rule', 'comment', 'place-before', 'disabled'})} are not allowed")
    if attrs.get("disabled", "no") != "no":
        raise WriteRefused("disabled must be no")
    if "place-before" in attrs and not ROS_ID.match(attrs["place-before"]):
        raise WriteRefused("place-before must be a rule id")
    chain, rule, cmt = attrs.get("chain", ""), attrs.get("rule", ""), attrs.get("comment", "")
    j = STEER_JUMP.match(cmt)
    if j:
        if not CHAIN_NAME.match(chain) or STEER_CHAIN.match(chain) or rule != f"jump shield-steer-{j.group(1)}":
            raise WriteRefused("the steering jump must be 'jump shield-steer-<upstream>' in that upstream's output chain")
        return
    if not STEER_CHAIN.match(chain):
        raise WriteRefused("Shield's steering rules must be in a shield-steer-<upstream> chain")
    if not COMMENT.match(cmt) or cmt == JUMP_COMMENT:
        raise WriteRefused("every steering rule must carry a shield:<action>:<n> comment")
    m = next((r.match(rule) for r in STEER_RULES if r.match(rule)), None)
    if m is None:
        raise WriteRefused("steering rules may only withhold, prepend or tag one exact prefix")
    try:
        net = ipaddress.ip_network(m.group("pfx"), strict=True)
    except ValueError:
        raise WriteRefused("the rule's prefix is not valid") from None
    lo, hi = (8, 24) if net.version == 4 else (16, 48)
    if not lo <= net.prefixlen <= hi:
        raise WriteRefused(f"steering applies to announced prefixes (/{lo}-/{hi}), not {net}")


def check_filter_write(words: list[str], owned) -> None:
    """Raise WriteRefused unless `words` is a read, or one of the allowed filter changes.
    `owned`: rule ids per table path that this session has read with a shield: comment."""
    if not words:
        raise WriteRefused("empty command")
    cmd = words[0]
    if cmd in ("/login", "/quit") or READ_COMMAND.match(cmd):
        check_read_only(words)
        return
    base, _, verb = cmd.rpartition("/")
    if (base not in RAW.values() and base != ROUTING_RULES) or verb not in ("add", "remove"):
        raise WriteRefused(f"Shield's filter account may only add or remove its own firewall raw and routing filter "
                           f"rules, not {cmd!r}")
    attrs: dict[str, str] = {}
    for w in words[1:]:
        if not w.startswith("=") or "\n" in w or "\r" in w:
            raise WriteRefused(f"unexpected word {w!r}")
        k, _, v = w[1:].partition("=")
        if k in attrs:
            raise WriteRefused(f"argument {k!r} given twice")
        attrs[k] = v
    if verb == "remove":
        if set(attrs) != {"numbers"} or not ROS_ID.match(attrs["numbers"]):
            raise WriteRefused("remove takes exactly one rule id")
        if attrs["numbers"] not in _owned(owned, base):
            raise WriteRefused(f"rule {attrs['numbers']} is not one of Shield's rules (or was not read first)")
        return
    if base == ROUTING_RULES:
        check_steer_add(attrs)
        return
    if not set(attrs) <= ADD_ATTRS:
        raise WriteRefused(f"argument(s) {sorted(set(attrs) - ADD_ATTRS)} are not allowed")
    if not COMMENT.match(attrs.get("comment", "")):
        raise WriteRefused("every rule Shield adds must carry a shield:<action>:<n> comment")
    if attrs.get("disabled", "no") != "no":
        raise WriteRefused("disabled must be no")
    if "place-before" in attrs and not ROS_ID.match(attrs["place-before"]):
        raise WriteRefused("place-before must be a rule id")
    if attrs["comment"] == JUMP_COMMENT:
        want = {"chain": "prerouting", "action": "jump", "jump-target": CHAIN}
        extra = set(attrs) - set(want) - {"comment", "place-before", "disabled"}
        if any(attrs.get(k) != v for k, v in want.items()) or extra:
            raise WriteRefused("the jump rule must be: chain=prerouting action=jump jump-target=shield-filter")
        return
    if attrs.get("chain") != CHAIN or attrs.get("action") != "drop" or "jump-target" in attrs:
        raise WriteRefused(f"Shield's rules must be chain={CHAIN} action=drop")
    try:
        net = ipaddress.ip_network(attrs.get("dst-address", ""), strict=True)
    except ValueError:
        raise WriteRefused("dst-address must be an address or prefix") from None
    if (net.version == 4) != base.startswith("/ip/"):
        raise WriteRefused("address family does not match the table")
    if net.prefixlen < (24 if net.version == 4 else 48):
        raise WriteRefused("dst-address is broader than a /24 (/48)")
    proto = attrs.get("protocol")
    if proto is not None and proto not in PROTOCOLS:
        raise WriteRefused(f"protocol {proto!r} is not allowed")
    for k in ("src-port", "dst-port"):
        if k in attrs and (proto not in ("udp", "tcp") or not _port(attrs[k])):
            raise WriteRefused(f"{k} needs protocol udp/tcp and a port 1-65535")
    if "fragment" in attrs and attrs["fragment"] != "yes":
        raise WriteRefused("fragment must be yes")
    if not ({"protocol", "fragment"} & set(attrs)):
        raise WriteRefused("a rule must match a protocol or fragments, never all traffic to an address "
                           "(that would be a blackhole: use RTBH)")


class FilterClient(ReadOnlyClient):
    """Read-only client that may also add and remove Shield's own firewall raw rules."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.owned: dict[str, set[str]] = {}

    def _guard(self, words: list[str]) -> None:
        check_filter_write(words, self.owned)

    def shield_rules(self, family: int) -> list[dict]:
        """Shield's rules in the raw table (comment shield:...), with counters; remembers their ids."""
        rows = self.print(RAW[family], stats=True)
        out = [r for r in rows if (r.get("comment") or "").startswith("shield:")]
        self.owned.setdefault(RAW[family], set()).update(r[".id"] for r in out if r.get(".id"))
        return out

    def first_rule_id(self, family: int) -> str | None:
        rows = self.print(RAW[family], proplist=[".id", "chain"], queries=["chain=prerouting"])
        return rows[0].get(".id") if rows else None

    def _add(self, path: str, attrs: dict[str, str]) -> str | None:
        done = self._talk([f"{path}/add"] + [f"={k}={v}" for k, v in attrs.items()])[-1]
        rid = done.get("ret")
        if rid:
            self.owned.setdefault(path, set()).add(rid)
        return rid

    def _remove(self, path: str, rule_id: str) -> None:
        self._talk([f"{path}/remove", f"=numbers={rule_id}"])
        self.owned.get(path, set()).discard(rule_id)

    def add(self, family: int, attrs: dict[str, str]) -> str | None:
        return self._add(RAW[family], attrs)

    def remove(self, family: int, rule_id: str) -> None:
        self._remove(RAW[family], rule_id)

    # --- steering: BGP output filter rules ---------------------------------------------------
    def steer_rules(self) -> list[dict]:
        """Shield's routing filter rules (comment shield:...), including the steering jumps."""
        rows = self.print(ROUTING_RULES)
        out = [r for r in rows if (r.get("comment") or "").startswith("shield:")]
        self.owned.setdefault(ROUTING_RULES, set()).update(r[".id"] for r in out if r.get(".id"))
        return out

    def first_rule_in(self, chain: str) -> str | None:
        rows = self.print(ROUTING_RULES, proplist=[".id", "chain"], queries=[f"chain={chain}"])
        return rows[0].get(".id") if rows else None

    def add_steer(self, attrs: dict[str, str]) -> str | None:
        return self._add(ROUTING_RULES, attrs)

    def remove_steer(self, rule_id: str) -> None:
        self._remove(ROUTING_RULES, rule_id)
