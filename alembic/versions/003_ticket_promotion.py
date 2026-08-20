"""Ticket promotion columns — promoted_at / promoted_by.

Revision ID: 003
Revises: 002
Create Date: 2026-08-19

"""

import sqlalchemy as sa

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tickets",
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tickets",
        sa.Column("promoted_by", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tickets", "promoted_by")
    op.drop_column("tickets", "promoted_at")
