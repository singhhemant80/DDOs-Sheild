"""FRR speaker: session fields and speaker settings

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-26 13:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None

SETTINGS = [  # frozen copy
    ("bgp_speaker", "simulated", "Where blackhole routes are announced: 'simulated' (nothing leaves Shield) or 'frr' (Shield's FRR BGP speaker; staging peers only in this release)."),
    ("bgp_router_id", "", "BGP router ID of Shield's FRR speaker (an IPv4 address of this server)."),
    ("rtbh_discard_nexthop_v4", "192.0.2.1", "IPv4 next hop on blackhole routes when the provider policy sets none (a discard address)."),
    ("rtbh_discard_nexthop_v6", "100::1", "IPv6 next hop on blackhole routes when the provider policy sets none (RFC 6666 discard prefix)."),
]


def upgrade() -> None:
    op.add_column('bgp_neighbors', sa.Column('environment', sa.String(length=16), server_default='staging', nullable=False))
    op.add_column('bgp_neighbors', sa.Column('remote_port', sa.Integer(), server_default='179', nullable=False))
    op.add_column('bgp_neighbors', sa.Column('ebgp_multihop', sa.SmallInteger(), nullable=True))
    op.add_column('bgp_neighbors', sa.Column('md5_password_enc', sa.Text(), nullable=True))
    op.add_column('bgp_neighbors', sa.Column('description', sa.String(length=200), nullable=True))
    op.create_check_constraint('ck_bgp_environment', 'bgp_neighbors', "environment IN ('staging', 'production')")
    op.create_check_constraint('ck_bgp_port', 'bgp_neighbors', 'remote_port BETWEEN 1 AND 65535')
    op.create_check_constraint('ck_bgp_multihop', 'bgp_neighbors', 'ebgp_multihop IS NULL OR ebgp_multihop BETWEEN 1 AND 255')
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])


def downgrade() -> None:
    op.execute("DELETE FROM system_settings WHERE key IN (%s)" % ", ".join(f"'{k}'" for k, _, _ in SETTINGS))
    for c in ('ck_bgp_multihop', 'ck_bgp_port', 'ck_bgp_environment'):
        op.drop_constraint(c, 'bgp_neighbors', type_='check')
    for c in ('description', 'md5_password_enc', 'ebgp_multihop', 'remote_port', 'environment'):
        op.drop_column('bgp_neighbors', c)
