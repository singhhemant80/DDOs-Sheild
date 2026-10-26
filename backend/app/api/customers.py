from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.orm import Session

from .. import audit
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import CustomerIpAssignment, ProtectedPrefix
from ..rbac import Perm
from ..schemas import CustomerIpCreate, CustomerIpOut

router = APIRouter(prefix="/customers", tags=["customers"])


@router.get("/ips", response_model=list[CustomerIpOut])
def list_ips(customer_ref: str | None = Query(None, max_length=64), limit: int = Query(500, le=5000),
             offset: int = Query(0, ge=0), _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(CustomerIpAssignment).order_by(CustomerIpAssignment.address)
    if customer_ref:
        q = q.where(CustomerIpAssignment.customer_ref == customer_ref)
    return db.execute(q.limit(limit).offset(offset)).scalars().all()


@router.post("/ips", response_model=CustomerIpOut, status_code=201)
def create_ip(body: CustomerIpCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
              db: Session = Depends(get_db)):
    pp = db.execute(
        select(ProtectedPrefix).where(cast(body.address, CIDR).op("<<=")(ProtectedPrefix.prefix))
    ).scalar_one_or_none()
    if pp is None:
        raise HTTPException(422,
                            f"{body.address} is not inside any protected prefix")
    c = CustomerIpAssignment(**body.model_dump(), protected_prefix_id=pp.id)
    db.add(c)
    record_change(db, p.actor, "customer_ip.create", "customer_ip", c)
    return c


@router.delete("/ips/{assignment_id}", status_code=204)
def delete_ip(assignment_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)), db: Session = Depends(get_db)):
    c = db.get(CustomerIpAssignment, assignment_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assignment not found")
    before = audit.snapshot(c)
    db.delete(c)
    record_change(db, p.actor, "customer_ip.delete", "customer_ip", None, entity_id=assignment_id, before=before)
