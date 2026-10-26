from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import cast, exists, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import audit
from .. import telemetry
from .. import netvalidate as nv
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import CustomerIpAssignment, MitigationAction, ProtectedPrefix, TERMINAL_ACTION_STATES, UpstreamProvider
from ..rbac import Perm
from ..schemas import EligibilityOut, PrefixCreate, PrefixOut, PrefixUpdate

router = APIRouter(prefix="/prefixes", tags=["prefixes"])

_MITIGATION_FLAGS = ("rtbh_allowed", "steering_allowed", "filtering_allowed")


def _get(db: Session, prefix_id: int) -> ProtectedPrefix:
    p = db.get(ProtectedPrefix, prefix_id)
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Protected prefix not found")
    return p


def _check_upstream(db: Session, upstream_id: int | None):
    if upstream_id is not None and db.get(UpstreamProvider, upstream_id) is None:
        raise HTTPException(422, "preferred_upstream_id does not exist")


@router.get("", response_model=list[PrefixOut])
def list_prefixes(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return db.execute(select(ProtectedPrefix).order_by(ProtectedPrefix.prefix)).scalars().all()


@router.get("/eligibility", response_model=EligibilityOut)
def eligibility(target: str = Query(..., description="IP address or prefix"),
                _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Explain whether a destination may be mitigated, and by which strategies. Read-only."""
    try:
        net = nv.parse_target(target)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return eligibility_for(db, net)


def eligibility_for(db: Session, net) -> EligibilityOut:
    pp = db.execute(
        select(ProtectedPrefix).where(cast(str(net), CIDR).op("<<=")(ProtectedPrefix.prefix))
    ).scalar_one_or_none()
    reasons: list[str] = []
    if pp is None:
        return EligibilityOut(target=str(net), protected_prefix=None, protected_prefix_id=None, enabled=False,
                              rtbh_allowed=False, steering_allowed=False, filtering_allowed=False,
                              within_scope_limit=False, customer=None,
                              reasons=["Target is not inside any protected prefix; no mitigation is permitted."])
    within = net.prefixlen >= pp.min_mitigation_prefix_len
    if not pp.enabled:
        reasons.append("Protected prefix is disabled.")
    if not pp.ownership_verified:
        reasons.append("Ownership of the protected prefix has not been verified.")
    if not within:
        reasons.append(f"Target /{net.prefixlen} is broader than the allowed /{pp.min_mitigation_prefix_len}.")
    cust = db.execute(
        select(CustomerIpAssignment).where(cast(str(net), CIDR).op("<<=")(CustomerIpAssignment.address))
    ).scalar_one_or_none()
    rtbh = pp.enabled and pp.rtbh_allowed and within
    if cust and cust.rtbh_opt_out:
        rtbh = False
        reasons.append("Customer has opted out of RTBH.")
    for flag in _MITIGATION_FLAGS:
        if not getattr(pp, flag):
            reasons.append(f"{flag} is false on the protected prefix.")
    return EligibilityOut(
        target=str(net), protected_prefix=str(pp.prefix), protected_prefix_id=pp.id, enabled=pp.enabled,
        rtbh_allowed=rtbh, steering_allowed=pp.enabled and pp.steering_allowed,
        filtering_allowed=pp.enabled and pp.filtering_allowed and within, within_scope_limit=within,
        customer=None if cust is None else {"customer_ref": cust.customer_ref, "customer_name": cust.customer_name,
                                            "service_type": cust.service_type.value, "address": str(cust.address)},
        reasons=reasons,
    )


@router.get("/{prefix_id}", response_model=PrefixOut)
def get_prefix(prefix_id: int, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return _get(db, prefix_id)


@router.post("", response_model=PrefixOut, status_code=201)
def create_prefix(body: PrefixCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                  db: Session = Depends(get_db)):
    _check_upstream(db, body.preferred_upstream_id)
    net = nv.parse_prefix(body.prefix)
    data = body.model_dump()
    if data["min_mitigation_prefix_len"] is None:
        data["min_mitigation_prefix_len"] = net.max_prefixlen  # host routes only by default
    if data["min_mitigation_prefix_len"] < net.prefixlen or data["min_mitigation_prefix_len"] > net.max_prefixlen:
        raise HTTPException(422,
                            f"min_mitigation_prefix_len must be between {net.prefixlen} and {net.max_prefixlen}")
    pp = ProtectedPrefix(**data)
    if any(data[f] for f in _MITIGATION_FLAGS):
        pp.authorized_by_id = p.user.id
        pp.authorized_at = datetime.now(UTC)
    db.add(pp)
    record_change(db, p.actor, "prefix.create", "protected_prefix", pp)
    telemetry.publish_prefixes(db)
    return pp


@router.patch("/{prefix_id}", response_model=PrefixOut)
def update_prefix(prefix_id: int, body: PrefixUpdate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                  db: Session = Depends(get_db)):
    pp = _get(db, prefix_id)
    before = audit.snapshot(pp)
    data = body.model_dump(exclude_unset=True)
    _check_upstream(db, data.get("preferred_upstream_id"))
    net = nv.parse_prefix(str(pp.prefix))
    if "min_mitigation_prefix_len" in data and data["min_mitigation_prefix_len"] is not None:
        if not net.prefixlen <= data["min_mitigation_prefix_len"] <= net.max_prefixlen:
            raise HTTPException(422,
                                f"min_mitigation_prefix_len must be between {net.prefixlen} and {net.max_prefixlen}")
    for k, v in data.items():
        if v is None and k in ("min_mitigation_prefix_len", "enabled", "ownership_verified", *_MITIGATION_FLAGS):
            continue
        setattr(pp, k, v)
    if any(getattr(pp, f) for f in _MITIGATION_FLAGS):
        if not (pp.ownership_verified and pp.ownership_evidence):
            raise HTTPException(422,
                                "enabling any mitigation requires ownership_verified=true and ownership_evidence")
        if any(data.get(f) and not before[f] for f in _MITIGATION_FLAGS):
            pp.authorized_by_id = p.user.id
            pp.authorized_at = datetime.now(UTC)
    record_change(db, p.actor, "prefix.update", "protected_prefix", pp, before=before)
    telemetry.publish_prefixes(db)
    return pp


@router.delete("/{prefix_id}", status_code=204)
def delete_prefix(prefix_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    pp = _get(db, prefix_id)
    live = db.execute(select(exists().where(
        MitigationAction.protected_prefix_id == pp.id, MitigationAction.state.notin_(TERMINAL_ACTION_STATES)
    ))).scalar()
    if live:
        raise HTTPException(status.HTTP_409_CONFLICT, "Prefix has live mitigation actions; withdraw them first")
    if db.execute(select(exists().where(CustomerIpAssignment.protected_prefix_id == pp.id))).scalar():
        raise HTTPException(status.HTTP_409_CONFLICT, "Prefix has customer IP assignments; remove them first")
    before = audit.snapshot(pp)
    db.delete(pp)
    record_change(db, p.actor, "prefix.delete", "protected_prefix", None, entity_id=prefix_id, before=before)
    telemetry.publish_prefixes(db)
