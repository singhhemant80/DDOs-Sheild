"""Reports and production readiness (Phase 10)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from .. import hardening, reports
from ..db import get_db
from ..deps import Principal, require
from ..rbac import Perm

router = APIRouter(tags=["reports"])


@router.get("/reports/summary")
def report_summary(days: int = Query(30, ge=1, le=3650), since: datetime | None = None, until: datetime | None = None,
                   _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Attacks, their size, targets, source networks and the mitigations taken, for a period."""
    return reports.summary(db, days=days, since=since, until=until)


@router.get("/reports/incidents.csv")
def report_csv(days: int = Query(30, ge=1, le=3650), since: datetime | None = None, until: datetime | None = None,
               _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    body = reports.incidents_csv(db, days=days, since=since, until=until)
    return Response(body, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="shield-attacks-{days}d.csv"'})


@router.get("/system/hardening")
def system_hardening(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Production readiness and hardening checks (read-only)."""
    items = hardening.checks(db)
    return {**hardening.summary(items), "checks": items}
