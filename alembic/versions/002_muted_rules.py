"""Muted rules table + alerts.muted flag.

Revision ID: 002
Revises: 001
Create Date: 2026-08-19

"""

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "muted_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_id", sa.String(50), nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.add_column(
        "alerts",
        sa.Column("muted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index("ix_alerts_muted", "alerts", ["muted"])


def downgrade() -> None:
    op.drop_index("ix_alerts_muted", table_name="alerts")
    op.drop_column("alerts", "muted")
    op.drop_table("muted_rules")
