"""Action state machine, timeline rows and live events.

    proposed --approve--> approved --> executing --> active --withdraw--> withdrawing --> withdrawn
        \\--reject/expire--> rejected     \\--> failed --> rolled_back
                              approved --emergency stop--> rejected

Every transition writes a mitigation_action_events row in the same transaction. Live messages
({"type": "mitigation"} on shield:events) are sent only after that transaction commits, so the
dashboard never shows a state the database does not have.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import redis
from sqlalchemy import event
from sqlalchemy.orm import Session

from .. import telemetry as tm
from ..models import ActionState as S
from ..models import AttackIncidentEvent, MitigationAction, MitigationActionEvent

log = logging.getLogger("shield.mitigation")
CHAN_EVENTS = "shield:events"

ALLOWED: dict[S, set[S]] = {
    S.PROPOSED: {S.APPROVED, S.REJECTED},
    S.APPROVED: {S.EXECUTING, S.REJECTED},
    S.EXECUTING: {S.ACTIVE, S.FAILED, S.WITHDRAWING},
    S.ACTIVE: {S.WITHDRAWING},
    S.WITHDRAWING: {S.WITHDRAWN, S.FAILED},
    S.FAILED: {S.ROLLED_BACK, S.WITHDRAWING},
}
LIVE = (S.PROPOSED, S.APPROVED, S.EXECUTING, S.ACTIVE, S.WITHDRAWING)


class InvalidTransition(ValueError):
    pass


def now() -> datetime:
    return datetime.now(UTC)


def action_out(a: MitigationAction) -> dict:
    return {
        "id": str(a.id), "group_id": str(a.group_id) if a.group_id else None, "state": a.state.value,
        "strategy": a.strategy.value, "target": str(a.target), "upstream_id": a.upstream_id,
        "incident_id": str(a.incident_id) if a.incident_id else None, "policy_id": a.policy_id,
        "automatic": a.automatic, "dry_run": a.dry_run,
        "requested_by_id": str(a.requested_by_id) if a.requested_by_id else None,
        "approved_by_id": str(a.approved_by_id) if a.approved_by_id else None,
        "approved_at": a.approved_at.isoformat() if a.approved_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "started_at": a.started_at.isoformat() if a.started_at else None,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        "extensions": a.extensions, "attempts": a.attempts, "error": a.error,
        "rejected_reason": a.rejected_reason, "withdraw_reason": a.withdraw_reason,
        "route": (a.plan or {}).get("route"), "checks": (a.plan or {}).get("checks", []),
        "impact": a.impact or {},
    }


def _pending(db: Session) -> list:
    return db.info.setdefault("shield_publish", [])


@event.listens_for(Session, "after_commit")
def _flush_publish(session: Session) -> None:
    msgs = session.info.pop("shield_publish", None)
    if not msgs:
        return
    try:
        r = tm.rds()
        for m in msgs:
            r.publish(CHAN_EVENTS, json.dumps(m, default=str))
    except redis.RedisError as e:
        log.warning("could not publish mitigation events: %s", e)


@event.listens_for(Session, "after_rollback")
def _drop_publish(session: Session) -> None:
    session.info.pop("shield_publish", None)


def record(db: Session, a: MitigationAction, to: S | None, actor: str, kind: str | None = None, **detail) -> None:
    """Timeline row (and live event) without a state change when `to` is None."""
    frm = a.state.value if a.state else None
    db.add(MitigationActionEvent(action_id=a.id, at=now(), from_state=frm,
                                 to_state=(to or a.state).value if (to or a.state) else "proposed",
                                 actor=actor[:64], detail={"kind": kind or (to.value if to else "note"), **detail}))
    _pending(db).append({"type": "mitigation", "event": kind or (to.value if to else "note"), "actor": actor,
                         "action": {"id": str(a.id), "target": str(a.target), "state": (to or a.state).value,
                                    "upstream_id": a.upstream_id, "incident_id": str(a.incident_id) if a.incident_id else None,
                                    "strategy": a.strategy.value if a.strategy else None, "dry_run": a.dry_run,
                                    "description": ((a.plan or {}).get("route") or {}).get("description")},
                         "detail": detail})


def transition(db: Session, a: MitigationAction, to: S, actor: str, kind: str | None = None, **detail) -> None:
    if a.state is not None and to not in ALLOWED.get(a.state, set()):
        raise InvalidTransition(f"cannot go from {a.state.value} to {to.value}")
    record(db, a, to, actor, kind, **detail)
    a.state = to
    if a.incident_id and to in (S.ACTIVE, S.WITHDRAWN, S.FAILED, S.ROLLED_BACK):
        route = (a.plan or {}).get("route") or {}
        word = {S.ACTIVE: "mitigation_active", S.WITHDRAWN: "mitigation_withdrawn",
                S.FAILED: "mitigation_failed", S.ROLLED_BACK: "mitigation_rolled_back"}[to]
        db.add(AttackIncidentEvent(incident_id=a.incident_id, at=now(), kind=word, actor=actor[:64],
                                   detail={"action_id": str(a.id), "route": route.get("description"),
                                           "simulation": a.dry_run, **detail}))
