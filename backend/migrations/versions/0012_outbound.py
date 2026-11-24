"""outbound attacks: incidents from local senders, outbound thresholds

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-24 19:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None

OPEN = "status IN ('suspected','confirmed','mitigating','mitigated')"
SETTINGS = [
    ("outbound_detection", True, "Detect attacks sent FROM your own addresses to the outside (a customer machine in a botnet, an open resolver used as an amplifier). Needs flow export for outgoing traffic."),
    ("outbound_pps", 50000, "Outbound: packets per second sent by one local address that count as an attack."),
    ("outbound_bps", 500000000, "Outbound: bits per second sent by one local address that count as an attack."),
    ("outbound_syn_pps", 10000, "Outbound: TCP SYN packets per second sent by one local address (SYN flood)."),
    ("outbound_udp_pps", 30000, "Outbound: UDP packets per second sent by one local address (UDP flood)."),
    ("outbound_icmp_pps", 10000, "Outbound: ICMP packets per second sent by one local address (ICMP flood)."),
    ("outbound_reflect_pps", 5000, "Outbound: UDP packets per second answered from a reflection port (DNS 53, NTP 123, SSDP 1900, ...): your server is being used as an amplifier."),
    ("outbound_scan_targets", 500, "Outbound: distinct outside addresses contacted per second by one local address (scanning)."),
]


def upgrade() -> None:
    op.add_column('attack_incidents', sa.Column('direction', sa.String(8), nullable=False, server_default='inbound'))
    op.create_check_constraint('ck_incident_direction', 'attack_incidents', "direction IN ('inbound', 'outbound')")
    # One open incident per target AND direction: a server can be attacked and attack others at once.
    op.drop_index('uq_incidents_open_target', table_name='attack_incidents', postgresql_where=sa.text(OPEN))
    op.create_index('uq_incidents_open_target', 'attack_incidents', ['target', 'direction'], unique=True,
                    postgresql_where=sa.text(OPEN))
    op.create_index('ix_incidents_direction', 'attack_incidents', ['direction'])
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": k, "value": v, "description": d} for k, v, d in SETTINGS])


def downgrade() -> None:
    op.execute("DELETE FROM system_settings WHERE key IN (%s)" % ", ".join(f"'{k}'" for k, _, _ in SETTINGS))
    op.drop_index('ix_incidents_direction', table_name='attack_incidents')
    op.execute("DELETE FROM attack_incidents WHERE direction = 'outbound'")
    op.drop_index('uq_incidents_open_target', table_name='attack_incidents', postgresql_where=sa.text(OPEN))
    op.create_index('uq_incidents_open_target', 'attack_incidents', ['target'], unique=True,
                    postgresql_where=sa.text(OPEN))
    op.drop_constraint('ck_incident_direction', 'attack_incidents', type_='check')
    op.drop_column('attack_incidents', 'direction')
