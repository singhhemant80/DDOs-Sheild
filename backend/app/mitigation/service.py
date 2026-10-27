"""Operations shared by the API and the controller: propose, re-check, approve, reject, withdraw."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..changes import get_setting
from ..models import ActionState as S
from ..models import MitigationAction, Strategy
from .planner import Plan, PlanRequest, build_plan
from .state import LIVE, now, record, transition


class Conflict(Exception):
    def __init__(self, message: str, checks: list | None = None):
        super().__init__(message)
        self.checks = checks or []


def request_fingerprint(req: PlanRequest) -> str:
    body = {"target": req.target, "strategy": req.strategy, "upstreams": sorted(req.upstream_ids or []),
            "incident": req.incident_id, "duration": req.duration_seconds}
    if req.router_ids is not None or req.filters is not None:
        body |= {"routers": sorted(req.router_ids or []), "filters": req.filters}
    if req.steering is not None:
        body |= {"steering": req.steering}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def existing_for_key(db: Session, key: str) -> list[MitigationAction]:
    return db.execute(select(MitigationAction).where(MitigationAction.idempotency_key.startswith(f"{key}#", autoescape=True))
                      .order_by(MitigationAction.created_at)).scalars().all()


def propose(db: Session, req: PlanRequest, *, key: str, actor: str, user_id=None, policy_id: int | None = None,
            plan: Plan | None = None) -> list[MitigationAction]:
    """Create one proposed action per route. Idempotent on `key`: the same key with the same request
    returns the actions already created; the same key with a different request is a conflict."""
    fp = request_fingerprint(req)
    prior = existing_for_key(db, key)
    if prior:
        if (prior[0].plan or {}).get("request_fingerprint") != fp:
            raise Conflict("This Idempotency-Key was already used for a different request.")
        return prior
    plan = plan or build_plan(db, req)
    if plan.blocked:
        raise Conflict("The plan is blocked by safety checks.", plan["checks"])
    group = uuid.uuid4()
    out = []
    for r in plan["routes"]:
        a = MitigationAction(
            id=uuid.uuid4(), idempotency_key=f"{key}#{r['peer']}"[:128], group_id=group,
            incident_id=uuid.UUID(req.incident_id) if req.incident_id else None, policy_id=policy_id,
            strategy=Strategy(req.strategy), target=plan["target"], protected_prefix_id=plan["protected_prefix_id"],
            upstream_id=r["upstream_id"], router_id=r.get("router_id"), state=None, dry_run=plan.get("simulation", True), automatic=req.automatic,
            requested_by_id=user_id, timeout_seconds=60,
            plan={"route": r, "checks": plan["checks"], "duration_seconds": plan["duration_seconds"],
                  "request_fingerprint": fp, "simulation": plan.get("simulation", True),
                  "acceptance_peer": req.acceptance_peer,
                  "speaker": plan.get("speaker", "simulated")},
            impact=plan["impact"], expected_state={"announced": [r["peer"] + "|" + r["prefix"]]})
        db.add(a)
        transition(db, a, S.PROPOSED, actor, "proposed", automatic=req.automatic)
        out.append(a)
    db.flush()
    return out


def recheck(db: Session, actions: list[MitigationAction], *, automatic: bool = False,
            auto_approve: bool = False) -> Plan:
    a0 = actions[0]
    req = PlanRequest(target=str(a0.target), strategy=a0.strategy.value,
                      upstream_ids=[a.upstream_id for a in actions if a.upstream_id is not None]
                      if a0.strategy == Strategy.RTBH_UPSTREAM else None,
                      incident_id=str(a0.incident_id) if a0.incident_id else None,
                      duration_seconds=(a0.plan or {}).get("duration_seconds"), automatic=automatic,
                      auto_approve=auto_approve, acceptance_peer=(a0.plan or {}).get("acceptance_peer"),
                      exclude_action_ids=[str(a.id) for a in actions])
    if a0.strategy == Strategy.STEERING:
        req.steering = [s for a in actions for s in (((a.plan or {}).get("route") or {}).get("steering") or [])]
    if a0.strategy == Strategy.LOCAL_FILTER:
        req.router_ids = [a.router_id for a in actions if a.router_id is not None]
        req.filters = list(((a0.plan or {}).get("route") or {}).get("filters") or [])
    return build_plan(db, req)


def approve(db: Session, actions: list[MitigationAction], *, actor: str, user_id, mfa: bool) -> Plan:
    if not actions or any(a.state != S.PROPOSED for a in actions):
        raise Conflict("Only proposed actions can be approved.")
    if get_setting(db, "require_mfa_for_mitigation", False) and not mfa:
        raise Conflict("Approving a mitigation needs a session signed in with MFA.")
    if get_setting(db, "four_eyes_approval", False) and any(a.requested_by_id == user_id for a in actions):
        raise Conflict("Four-eyes approval is on: someone other than the proposer must approve.")
    plan = recheck(db, actions)
    if plan.blocked:
        raise Conflict("The situation changed since it was proposed; the plan is now blocked.", plan["checks"])
    t = now()
    for a in actions:
        a.approved_by_id, a.approved_at = user_id, t
        a.plan = {**a.plan, "checks_at_approval": plan["checks"]}
        transition(db, a, S.APPROVED, actor, "approved")
    return plan


def reject(db: Session, actions: list[MitigationAction], *, actor: str, reason: str) -> None:
    for a in actions:
        if a.state not in (S.PROPOSED, S.APPROVED):
            raise Conflict(f"A {a.state.value} action cannot be rejected; withdraw it instead.")
    for a in actions:
        a.rejected_reason = reason
        a.completed_at = now()
        transition(db, a, S.REJECTED, actor, "rejected", reason=reason)


def withdraw(db: Session, a: MitigationAction, *, actor: str, user_id=None, reason: str) -> None:
    if a.state in (S.PROPOSED, S.APPROVED):
        reject(db, [a], actor=actor, reason=f"cancelled: {reason}")
        return
    if a.state not in (S.EXECUTING, S.ACTIVE, S.FAILED):
        raise Conflict(f"A {a.state.value} action cannot be withdrawn.")
    a.withdrawn_by_id, a.withdraw_reason = user_id, reason
    transition(db, a, S.WITHDRAWING, actor, "withdraw_requested", reason=reason)


def extend(db: Session, a: MitigationAction, seconds: int, *, actor: str, why: str) -> None:
    if a.state != S.ACTIVE:
        raise Conflict("Only active actions can be extended.")
    a.expires_at = max(a.expires_at or now(), now()) + timedelta(seconds=seconds)
    a.extensions += 1
    record(db, a, None, actor, "extended", until=a.expires_at.isoformat(), why=why)


def group_of(db: Session, a: MitigationAction) -> list[MitigationAction]:
    if a.group_id is None:
        return [a]
    return db.execute(select(MitigationAction).where(MitigationAction.group_id == a.group_id)
                      .order_by(MitigationAction.created_at)).scalars().all()


__all__ = ["Conflict", "LIVE", "approve", "extend", "group_of", "propose", "recheck", "reject", "withdraw"]
