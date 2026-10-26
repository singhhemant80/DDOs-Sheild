"""per-incident source summary

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-26 21:30:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('attack_incidents', sa.Column('sources_summary', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('attack_incidents', 'sources_summary')
