"""scrubbing-centre adapter (Phase 9 part 3)

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-27 09:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def _fn(strategies: str) -> str:
    return f"""
CREATE OR REPLACE FUNCTION shield_action_in_prefix() RETURNS trigger AS $$
DECLARE pfx cidr; minlen smallint;
BEGIN
    SELECT prefix, min_mitigation_prefix_len INTO pfx, minlen
      FROM protected_prefixes WHERE id = NEW.protected_prefix_id AND enabled;
    IF pfx IS NULL OR NOT (NEW.target <<= pfx) THEN
        RAISE EXCEPTION 'mitigation target % is not inside an enabled protected prefix', NEW.target
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.strategy IN ({strategies}) THEN
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


def upgrade() -> None:
    # Scrubbing, like steering, diverts a whole announced prefix and drops nothing itself.
    op.execute(_fn("'steering', 'scrubbing'"))
    op.add_column('protected_prefixes', sa.Column('scrubbing_allowed', sa.Boolean(), server_default='false', nullable=False))
    op.create_table('scrubbing_providers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('auth_header', sa.String(length=64), nullable=True),
        sa.Column('secret_enc', sa.Text(), nullable=True),
        sa.Column('documentation_ref', sa.Text(), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('min_prefix_len', sa.SmallInteger(), nullable=False),
        sa.Column('max_prefix_len', sa.SmallInteger(), nullable=False),
        sa.Column('max_prefixes', sa.Integer(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("method IN ('api','manual')", name='ck_scrubbing_method'),
        sa.CheckConstraint('min_prefix_len <= max_prefix_len', name='ck_scrubbing_lengths'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'))
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": "scrubbing_backend", "value": "simulated",
                        "description": "Where scrubbing requests go: 'simulated' (no provider is called) or 'live' (Shield calls the provider's API)."}])


def downgrade() -> None:
    op.execute(_fn("'steering'"))
    op.execute("DELETE FROM system_settings WHERE key = 'scrubbing_backend'")
    op.drop_table('scrubbing_providers')
    op.drop_column('protected_prefixes', 'scrubbing_allowed')
