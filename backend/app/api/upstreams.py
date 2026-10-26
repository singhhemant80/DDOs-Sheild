from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .. import audit
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import Router, UpstreamProvider, UpstreamRtbhPolicy
from ..rbac import Perm
from ..schemas import RtbhPolicyIn, RtbhPolicyOut, UpstreamCreate, UpstreamOut, UpstreamUpdate

router = APIRouter(prefix="/upstreams", tags=["upstreams"])


def _get(db: Session, upstream_id: int) -> UpstreamProvider:
    u = db.execute(select(UpstreamProvider).options(selectinload(UpstreamProvider.rtbh_policy))
                   .where(UpstreamProvider.id == upstream_id)).scalar_one_or_none()
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upstream not found")
    return u


def _check_router(db: Session, router_id: int | None):
    if router_id is not None and db.get(Router, router_id) is None:
        raise HTTPException(422, "router_id does not exist")


@router.get("", response_model=list[UpstreamOut])
def list_upstreams(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return db.execute(select(UpstreamProvider).options(selectinload(UpstreamProvider.rtbh_policy))
                      .order_by(UpstreamProvider.name)).scalars().all()


@router.get("/{upstream_id}", response_model=UpstreamOut)
def get_upstream(upstream_id: int, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return _get(db, upstream_id)


@router.post("", response_model=UpstreamOut, status_code=201)
def create_upstream(body: UpstreamCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    _check_router(db, body.router_id)
    u = UpstreamProvider(**body.model_dump())
    db.add(u)
    record_change(db, p.actor, "upstream.create", "upstream", u)
    return _get(db, u.id)


@router.patch("/{upstream_id}", response_model=UpstreamOut)
def update_upstream(upstream_id: int, body: UpstreamUpdate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    u = _get(db, upstream_id)
    before = audit.snapshot(u)
    data = body.model_dump(exclude_unset=True)
    _check_router(db, data.get("router_id"))
    for k, v in data.items():
        if v is not None or k in ("router_id", "interface_name", "capacity_mbps", "description"):
            setattr(u, k, v)
    record_change(db, p.actor, "upstream.update", "upstream", u, before=before)
    return u


@router.delete("/{upstream_id}", status_code=204)
def delete_upstream(upstream_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    u = _get(db, upstream_id)
    before = audit.snapshot(u)
    db.delete(u)
    record_change(db, p.actor, "upstream.delete", "upstream", None, entity_id=upstream_id, before=before)


# ---------------------------------------------------------------- RTBH policy
@router.put("/{upstream_id}/rtbh-policy", response_model=RtbhPolicyOut)
def put_rtbh_policy(upstream_id: int, body: RtbhPolicyIn, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    """Create or replace the upstream's RTBH rules. Any change disables the policy and clears
    verification, so a modified policy must be re-verified before it can be enabled again."""
    u = _get(db, upstream_id)
    pol = u.rtbh_policy
    before = audit.snapshot(pol) if pol else None
    if pol is None:
        pol = UpstreamRtbhPolicy(upstream_id=u.id)
        db.add(pol)
    for k, v in body.model_dump().items():
        setattr(pol, k, v)
    pol.enabled = False
    pol.verified_at = None
    pol.verified_by_id = None
    # New communities or next hop: the provider sessions must pass acceptance again.
    from ..models import BgpNeighbor
    for n in db.execute(select(BgpNeighbor).where(BgpNeighbor.upstream_id == u.id)).scalars():
        n.acceptance_passed_at = None
    record_change(db, p.actor, "rtbh_policy.put", "upstream_rtbh_policy", pol, before=before)
    return pol


def _policy(db: Session, upstream_id: int) -> UpstreamRtbhPolicy:
    pol = _get(db, upstream_id).rtbh_policy
    if pol is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No RTBH policy configured for this upstream")
    return pol


@router.post("/{upstream_id}/rtbh-policy/verify", response_model=RtbhPolicyOut)
def verify_rtbh_policy(upstream_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                       db: Session = Depends(get_db)):
    """Record that an engineer checked this policy against the provider's documentation."""
    pol = _policy(db, upstream_id)
    if not pol.documentation_ref:
        raise HTTPException(422,
                            "documentation_ref (provider RTBH documentation / ticket) is required before verification")
    if not pol.communities and not pol.next_hop:
        raise HTTPException(422, "Policy needs at least one community or a next_hop")
    before = audit.snapshot(pol)
    pol.verified_at = datetime.now(UTC)
    pol.verified_by_id = p.user.id
    record_change(db, p.actor, "rtbh_policy.verify", "upstream_rtbh_policy", pol, before=before)
    return pol


@router.post("/{upstream_id}/rtbh-policy/enable", response_model=RtbhPolicyOut)
def enable_rtbh_policy(upstream_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                       db: Session = Depends(get_db)):
    pol = _policy(db, upstream_id)
    if pol.verified_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Policy must be verified before it can be enabled")
    before = audit.snapshot(pol)
    pol.enabled = True
    record_change(db, p.actor, "rtbh_policy.enable", "upstream_rtbh_policy", pol, before=before)
    return pol


@router.post("/{upstream_id}/rtbh-policy/disable", response_model=RtbhPolicyOut)
def disable_rtbh_policy(upstream_id: int, p: Principal = Depends(require(Perm.AUTOMATION_STOP)),
                        db: Session = Depends(get_db)):
    """Disabling is a safety action, so NOC operators may do it."""
    pol = _policy(db, upstream_id)
    before = audit.snapshot(pol)
    pol.enabled = False
    record_change(db, p.actor, "rtbh_policy.disable", "upstream_rtbh_policy", pol, before=before)
    return pol
