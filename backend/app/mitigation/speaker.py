"""BGP speakers the mitigation controller announces through.

Phase 6 ships only SimulatedSpeaker: it keeps its "RIB" in Redis, separate from PostgreSQL, so the
controller's reconciliation is exercised for real (a crash between writing the database and
announcing leaves the two out of step, exactly as with a real speaker). Nothing leaves Shield.
Phase 7 adds an FRR speaker with the same interface.

Fault injection (lab and tests): SET shield:sim:fault to
  "announce"  - announcements fail
  "withdraw"  - withdrawals fail
  "verify"    - announcements are accepted but do not appear in the RIB (silent drop)
  "down"      - the speaker is unreachable
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Protocol

import redis

KEY_RIB = "shield:sim:rib"
KEY_FAULT = "shield:sim:fault"


class SpeakerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Route:
    """One announcement: a prefix towards one peer (an upstream, or "internal" for own routers)."""
    peer: str                       # "upstream:<id>" or "internal"
    prefix: str
    communities: tuple[str, ...] = ()
    next_hop: str | None = None
    no_export: bool = True
    action_id: str | None = None
    attrs: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def key(self) -> str:
        return f"{self.peer}|{self.prefix}"

    def same_attributes(self, other: "Route") -> bool:
        return (self.prefix, tuple(sorted(self.communities)), self.next_hop, self.no_export) == \
            (other.prefix, tuple(sorted(other.communities)), other.next_hop, other.no_export)

    def to_json(self) -> str:
        d = asdict(self)
        d["communities"] = list(self.communities)
        return json.dumps(d)

    @classmethod
    def from_json(cls, raw: str) -> "Route":
        d = json.loads(raw)
        d["communities"] = tuple(d.get("communities") or ())
        return cls(**d)


class Speaker(Protocol):
    name: str

    def announce(self, route: Route) -> None: ...
    def withdraw(self, route: Route) -> None: ...
    def routes(self) -> dict[str, Route]: ...


class SimulatedSpeaker:
    name = "simulated"

    def __init__(self, rds: redis.Redis):
        self.rds = rds

    def _fault(self) -> str | None:
        try:
            return self.rds.get(KEY_FAULT)
        except redis.RedisError as e:
            raise SpeakerError(f"speaker unreachable: {e}") from None

    def announce(self, route: Route) -> None:
        f = self._fault()
        if f in ("announce", "down"):
            raise SpeakerError("simulated speaker refused the announcement" if f == "announce" else "speaker unreachable")
        if f == "verify":
            return  # accepted, silently dropped
        stored = Route(**{**asdict(route), "communities": route.communities,
                          "attrs": {**route.attrs, "announced_at": time.time()}})
        self.rds.hset(KEY_RIB, route.key, stored.to_json())

    def withdraw(self, route: Route) -> None:
        f = self._fault()
        if f in ("withdraw", "down"):
            raise SpeakerError("simulated speaker refused the withdrawal" if f == "withdraw" else "speaker unreachable")
        self.rds.hdel(KEY_RIB, route.key)

    def routes(self) -> dict[str, Route]:
        if self._fault() == "down":
            raise SpeakerError("speaker unreachable")
        try:
            raw = self.rds.hgetall(KEY_RIB)
        except redis.RedisError as e:
            raise SpeakerError(f"speaker unreachable: {e}") from None
        return {k: Route.from_json(v) for k, v in raw.items()}
