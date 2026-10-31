"""alerting and reports (Phase 10)

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-31 09:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    t = sa.table("system_settings", sa.column("key", sa.String), sa.column("value", postgresql.JSONB),
                 sa.column("description", sa.Text))
    op.bulk_insert(t, [{"key": "dashboard_url", "value": "",
                        "description": "Address of this dashboard (e.g. https://shield.example.net), used for links in alerts."}])
    op.create_index('ix_notifications_status', 'notifications', ['status'])


def downgrade() -> None:
    op.drop_index('ix_notifications_status', table_name='notifications')
    op.execute("DELETE FROM system_settings WHERE key = 'dashboard_url'")
