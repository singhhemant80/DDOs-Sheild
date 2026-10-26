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
CHAIN = "shield-filter"
JUMP_COMMENT = "shield:jump"
COMMENT = re.compile(r"^shield:(?:jump|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9]{1,2})$")
ROS_ID = re.compile(r"^\*[0-9A-Fa-f]{1,8}$")
PROTOCOLS = {"udp", "tcp", "icmp", "icmpv6"}
ADD_ATTRS = {"chain", "action", "jump-target", "dst-address", "protocol", "src-port", "dst-port", "fragment",
             "comment", "place-before", "disabled"}


def _port(v: str) -> bool:
    return v.isdigit() and 1 <= int(v) <= 65535


def check_filter_write(words: list[str], owned: set[str]) -> None:
    """Raise WriteRefused unless `words` is a read, or one of the allowed filter changes."""
    if not words:
        raise WriteRefused("empty command")
    cmd = words[0]
    if cmd in ("/login", "/quit") or READ_COMMAND.match(cmd):
        check_read_only(words)
        return
    base, _, verb = cmd.rpartition("/")
    if base not in RAW.values() or verb not in ("add", "remove"):
        raise WriteRefused(f"Shield's filter account may only add or remove its own firewall raw rules, not {cmd!r}")
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
        if attrs["numbers"] not in owned:
            raise WriteRefused(f"rule {attrs['numbers']} is not one of Shield's rules (or was not read first)")
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
        self.owned: set[str] = set()

    def _guard(self, words: list[str]) -> None:
        check_filter_write(words, self.owned)

    def shield_rules(self, family: int) -> list[dict]:
        """Shield's rules in the raw table (comment shield:...), with counters; remembers their ids."""
        rows = self.print(RAW[family], stats=True)
        out = [r for r in rows if (r.get("comment") or "").startswith("shield:")]
        for r in out:
            if r.get(".id"):
                self.owned.add(r[".id"])
        return out

    def first_rule_id(self, family: int) -> str | None:
        rows = self.print(RAW[family], proplist=[".id", "chain"], queries=["chain=prerouting"])
        return rows[0].get(".id") if rows else None

    def add(self, family: int, attrs: dict[str, str]) -> str | None:
        done = self._talk([f"{RAW[family]}/add"] + [f"={k}={v}" for k, v in attrs.items()])[-1]
        rid = done.get("ret")
        if rid:
            self.owned.add(rid)
        return rid

    def remove(self, family: int, rule_id: str) -> None:
        self._talk([f"{RAW[family]}/remove", f"=numbers={rule_id}"])
        self.owned.discard(rule_id)
