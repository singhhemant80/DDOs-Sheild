"""selective upstream steering (Phase 9 part 2)

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-27 08:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None

SETTINGS = [
    ("steering_backend", "simulated", "Where steering rules go: 'simulated' (nothing changes on any router) or 'routeros' (Shield's filter account adds its own rules to the BGP output filter towards an upstream)."),
    ("steering_max_rules", 20, "Hard ceiling on Shield's steering rules across all upstreams."),
]


# Steering moves an announced prefix (a /24 or /48) between upstreams and drops nothing, so the
# per-prefix limit on how broad a blackhole may be does not apply; it may not be broader than that.
FN = """
CREATE OR REPLACE FUNCTION shield_action_in_prefix() RETURNS trigger AS $$
DECLARE pfx cidr; minlen smallint;
BEGIN
    SELECT prefix, min_mitigation_prefix_len INTO pfx, minlen
      FROM protected_prefixes WHERE id = NEW.protected_prefix_id AND enabled;
    IF pfx IS NULL OR NOT (NEW.target <<= pfx) THEN
        RAISE EXCEPTION 'mitigation target % is not inside an enabled protected prefix', NEW.target
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.strategy = 'steering' THEN
        IF (family(NEW.target) = 4 AND (masklen(NEW.target) < 8 OR masklen(NEW.target) > 24))
           OR (family(NEW.target) = 6 AND (masklen(NEW.target) < 16 OR masklen(NEW.target) > 48)) THEN
            RAISE EXCEPTION 'steering target % must be an announced prefix (/8-/24, /16-/48)', NEW.target
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF masklen(NEW.target) < minlen THEN
        RAISE EXCEPTION 'mitigation target % is broader than allowed /%', NEW.target, minlen
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""
FN_OLD = """
CREATE OR REPLACE FUNCTION shield_action_in_prefix() RETURNS trigger AS $$
DECLARE pfx cidr; minlen smallint;
BEGIN
    SELECT prefix, min_mitigation_prefix_len INTO pfx, minlen
      FROM protected_prefixes WHERE id = NEW.protected_prefix_id AND enabled;
    IF pfx IS NULL OR NOT (NEW.target <<= pfx) THEN
        RAISE EXCEPTION 'mitigation target % is not inside an enabled protected prefix', NEW.target
            USING ERRCODE = 'check_violation';
    END IF;
    IF masklen(NEW.target) < minlen THEN
        RAISE EXCEPTION 'mitigation target % is broader than allowed /%', NEW.target, minlen
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.execute(FN)
    op.add_column('filter_rules', sa.Column('kind', sa.String(length=8), server_default='filter', nullable=False))
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])


def downgrade() -> None:
    op.execute(FN_OLD)
    op.execute("DELETE FROM system_settings WHERE key IN ('steering_backend', 'steering_max_rules')")
    op.drop_column('filter_rules', 'kind')
