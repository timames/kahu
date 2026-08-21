"""Add per-instance poll cursor to connector_instances.

Native ingestion pollers (Azure/Defender/Entra) persist their position —
watermark, recently-seen event ids, and daily counter state — per connector
instance so ingestion survives restarts without re-draining or skipping.

Revision ID: 005
Revises: 004
"""

import sqlalchemy as sa

from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "connector_instances",
        sa.Column("cursor", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("connector_instances", "cursor")
