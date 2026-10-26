"""local filtering (Phase 9): router filter account, filter rule ledger, settings

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-26 22:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

LIVE = "state NOT IN ('rejected','withdrawn','rolled_back','failed')"
SETTINGS = [
    ("filter_backend", "simulated", "Where local filtering rules go: 'simulated' (nothing changes on any router) or 'routeros' (Shield's filter account adds its own drop rules to the router's firewall raw table)."),
    ("filter_max_rules", 50, "Hard ceiling on Shield's firewall drop rules across all routers."),
]


def upgrade() -> None:
    op.add_column('routers', sa.Column('filter_username', sa.String(length=64), nullable=True))
    op.add_column('routers', sa.Column('filter_password_enc', sa.Text(), nullable=True))
    op.create_table('filter_rules',
        sa.Column('id', sa.BigInteger(), nullable=False),
        sa.Column('action_id', sa.UUID(), nullable=False),
        sa.Column('router_id', sa.Integer(), nullable=True),
        sa.Column('comment', sa.String(length=128), nullable=False),
        sa.Column('match', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('backend', sa.String(length=16), nullable=False),
        sa.Column('router_rule_id', sa.String(length=32), nullable=True),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('packets', sa.BigInteger(), nullable=True),
        sa.Column('bytes', sa.BigInteger(), nullable=True),
        sa.Column('counted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("status IN ('pending','active','removing','removed','failed')", name='ck_filter_rules_status'),
        sa.CheckConstraint("comment LIKE 'shield:%'", name='ck_filter_rules_comment'),
        sa.ForeignKeyConstraint(['action_id'], ['mitigation_actions.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_filter_rules_status', 'filter_rules', ['status'])
    op.create_index('ix_filter_rules_action', 'filter_rules', ['action_id'])
    op.drop_index('uq_actions_live_target', table_name='mitigation_actions', postgresql_where=sa.text(LIVE))
    op.create_index('uq_actions_live_target', 'mitigation_actions',
                    ['strategy', 'target', sa.literal_column('coalesce(upstream_id, 0)'), sa.literal_column('coalesce(router_id, 0)')],
                    unique=True, postgresql_where=sa.text(LIVE))
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])


def downgrade() -> None:
    op.execute("DELETE FROM system_settings WHERE key IN ('filter_backend', 'filter_max_rules')")
    op.drop_index('uq_actions_live_target', table_name='mitigation_actions', postgresql_where=sa.text(LIVE))
    op.create_index('uq_actions_live_target', 'mitigation_actions',
                    ['strategy', 'target', sa.literal_column('coalesce(upstream_id, 0)')],
                    unique=True, postgresql_where=sa.text(LIVE))
    op.drop_index('ix_filter_rules_action', table_name='filter_rules')
    op.drop_index('ix_filter_rules_status', table_name='filter_rules')
    op.drop_table('filter_rules')
    op.drop_column('routers', 'filter_password_enc')
    op.drop_column('routers', 'filter_username')
