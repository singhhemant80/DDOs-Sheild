"""Helpers that make every configuration change audited and versioned in one transaction."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .audit import Actor
from .models import ConfigVersion, SystemSetting


def record_change(
    db: Session,
    actor: Actor,
    action: str,
    entity_type: str,
    obj=None,
    *,
    entity_id=None,
    before: dict | None = None,
    note: str | None = None,
) -> None:
    db.flush()
    after = audit.snapshot(obj) if obj is not None else None
    eid = str(entity_id if entity_id is not None else getattr(obj, "id", None))
    audit.record(db, actor, action, entity_type, eid, before=before, after=after)
    ver = db.execute(
        select(func.coalesce(func.max(ConfigVersion.version), 0)).where(
            ConfigVersion.entity_type == entity_type, ConfigVersion.entity_id == eid
        )
    ).scalar_one()
    db.add(ConfigVersion(entity_type=entity_type, entity_id=eid, version=ver + 1,
                         snapshot=audit._jsonable(after) if after else None,
                         changed_by_id=actor.user_id, change_note=note))


def apply_patch(obj, data: dict) -> dict:
    """Apply a partial update; returns {field: (old, new)} for fields that actually changed."""
    changed = {}
    for k, v in data.items():
        old = getattr(obj, k)
        if old != v:
            setattr(obj, k, v)
            changed[k] = (old, v)
    return changed


def get_setting(db: Session, key: str, default=None):
    row = db.get(SystemSetting, key)
    return default if row is None else row.value
