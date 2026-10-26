"""BGP neighbour inventory. Session state is populated from Phase 5 (RouterOS) / Phase 7 (FRR)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..changes import record_change
from ..db import get_db
from ..deps import Principal, require
from ..models import BgpNeighbor, Router, UpstreamProvider
from ..rbac import Perm
from ..schemas import BgpNeighborCreate, BgpNeighborOut

router = APIRouter(prefix="/bgp", tags=["bgp"])


@router.get("/neighbors", response_model=list[BgpNeighborOut])
def list_neighbors(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return db.execute(select(BgpNeighbor).order_by(BgpNeighbor.name)).scalars().all()


@router.post("/neighbors", response_model=BgpNeighborOut, status_code=201)
def create_neighbor(body: BgpNeighborCreate, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    if body.router_id is not None and db.get(Router, body.router_id) is None:
        raise HTTPException(422, "router_id does not exist")
    if body.upstream_id is not None:
        up = db.get(UpstreamProvider, body.upstream_id)
        if up is None:
            raise HTTPException(422, "upstream_id does not exist")
        if up.asn != body.remote_asn:
            raise HTTPException(422,
                                f"remote_asn {body.remote_asn} does not match upstream ASN {up.asn}")
    n = BgpNeighbor(**body.model_dump())
    db.add(n)
    record_change(db, p.actor, "bgp_neighbor.create", "bgp_neighbor", n)
    return n


@router.delete("/neighbors/{neighbor_id}", status_code=204)
def delete_neighbor(neighbor_id: int, p: Principal = Depends(require(Perm.CONFIG_NETWORK)),
                    db: Session = Depends(get_db)):
    n = db.get(BgpNeighbor, neighbor_id)
    if n is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Neighbor not found")
    before = audit.snapshot(n)
    db.delete(n)
    record_change(db, p.actor, "bgp_neighbor.delete", "bgp_neighbor", None, entity_id=neighbor_id, before=before)
