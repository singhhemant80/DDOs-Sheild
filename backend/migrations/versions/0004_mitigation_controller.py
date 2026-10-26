"""mitigation controller (simulation)

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-26 12:10:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None

# Frozen copy: migrations never import live application defaults.
SETTINGS = [
    ("internal_blackhole_community", "", "Community Shield attaches to internal blackhole routes sent to your own edge routers (e.g. 65535:666). Empty disables internal RTBH."),
    ("four_eyes_approval", False, "A mitigation must be approved by someone other than the person who proposed it."),
    ("proposal_ttl_minutes", 15, "Proposals not approved within this time expire; the situation has probably changed."),
    ("rtbh_flap_cooldown_seconds", 900, "After a blackhole is withdrawn, re-blackholing the same address within this time needs a human (no automatic re-announce)."),
    ("rtbh_default_duration_minutes", 60, "How long a manual blackhole lasts before it is reviewed for withdrawal (extended while the attack continues)."),
]


def upgrade() -> None:
    op.add_column('mitigation_actions', sa.Column('group_id', sa.UUID(), nullable=True))
    op.add_column('mitigation_actions', sa.Column('hold_until', sa.DateTime(timezone=True), nullable=True))
    op.add_column('mitigation_actions', sa.Column('extensions', sa.SmallInteger(), server_default='0', nullable=False))
    op.add_column('mitigation_actions', sa.Column('attempts', sa.SmallInteger(), server_default='0', nullable=False))
    op.add_column('mitigation_actions', sa.Column('withdrawn_by_id', sa.UUID(), nullable=True))
    op.add_column('mitigation_actions', sa.Column('withdraw_reason', sa.Text(), nullable=True))
    op.create_index('ix_actions_group', 'mitigation_actions', ['group_id'], unique=False)
    op.create_foreign_key('mitigation_actions_withdrawn_by_id_fkey', 'mitigation_actions', 'users',
                          ['withdrawn_by_id'], ['id'], ondelete='SET NULL')
    op.add_column('rtbh_routes', sa.Column('speaker', sa.String(length=16), server_default='simulated', nullable=False))
    settings_t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                          sa.column("description", sa.Text))
    op.bulk_insert(settings_t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])


def downgrade() -> None:
    op.execute("DELETE FROM system_settings WHERE key IN (%s)" % ", ".join(f"'{k}'" for k, _, _ in SETTINGS))
    op.drop_column('rtbh_routes', 'speaker')
    op.drop_constraint('mitigation_actions_withdrawn_by_id_fkey', 'mitigation_actions', type_='foreignkey')
    op.drop_index('ix_actions_group', table_name='mitigation_actions')
    for c in ('withdraw_reason', 'withdrawn_by_id', 'attempts', 'extensions', 'hold_until', 'group_id'):
        op.drop_column('mitigation_actions', c)
