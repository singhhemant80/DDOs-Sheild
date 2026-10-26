"""production gate and acceptance runs

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-26 19:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

SETTINGS = [("bgp_production_enabled", False,
             "Production BGP sessions are configured and may carry blackholes (each only after its acceptance run passes). Changed only through its own switch.")]

BGP_SPEAKER_DESC = "Where blackhole routes are announced: 'simulated' (nothing leaves Shield) or 'frr' (Shield's FRR BGP speaker: staging sessions, and production sessions once production is switched on)."
BGP_SPEAKER_DESC_OLD = "Where blackhole routes are announced: 'simulated' (nothing leaves Shield) or 'frr' (Shield's FRR BGP speaker; staging peers only in this release)."


def upgrade() -> None:
    op.create_table('acceptance_runs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('peer', sa.String(length=32), nullable=False),
        sa.Column('target', postgresql.CIDR(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('step', sa.String(length=32), nullable=False),
        sa.Column('action_id', sa.UUID(), nullable=True),
        sa.Column('started_by_id', sa.UUID(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('step_started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('baseline', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('error', sa.Text(), nullable=True),
        sa.CheckConstraint("status IN ('pending', 'running', 'passed', 'failed')", name='ck_acceptance_status'),
        sa.ForeignKeyConstraint(['action_id'], ['mitigation_actions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['started_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_acceptance_peer_started', 'acceptance_runs', ['peer', 'started_at'], unique=False)
    op.create_index('uq_acceptance_running_peer', 'acceptance_runs', ['peer'], unique=True,
                    postgresql_where=sa.text("status IN ('pending','running')"))
    op.add_column('bgp_neighbors', sa.Column('acceptance_passed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('bgp_neighbors', sa.Column('acceptance_run_id', sa.UUID(), nullable=True))
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])
    op.execute(t.update().where(t.c.key == "bgp_speaker").values(description=BGP_SPEAKER_DESC))


def downgrade() -> None:
    op.execute("DELETE FROM system_settings WHERE key = 'bgp_production_enabled'")
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("description", sa.Text))
    op.execute(t.update().where(t.c.key == "bgp_speaker").values(description=BGP_SPEAKER_DESC_OLD))
    op.drop_column('bgp_neighbors', 'acceptance_run_id')
    op.drop_column('bgp_neighbors', 'acceptance_passed_at')
    op.drop_index('uq_acceptance_running_peer', table_name='acceptance_runs', postgresql_where=sa.text("status IN ('pending','running')"))
    op.drop_index('ix_acceptance_peer_started', table_name='acceptance_runs')
    op.drop_table('acceptance_runs')
