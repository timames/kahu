"""Add monotonic sequence column to evidence for chain total order.

The hash chain previously used timestamp ordering, which is not a total
order under concurrent writers and allowed the chain to fork. `sequence`
gives every record an explicit chain position; appends are serialised by
an advisory lock in the evidence service.

Revision ID: 004
Revises: 003
"""

import sqlalchemy as sa

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("sequence", sa.BigInteger(), nullable=True))
    # Backfill in (timestamp, id) order — the best available approximation of
    # historical append order.
    op.execute(
        """
        UPDATE evidence SET sequence = s.rn
        FROM (SELECT id, row_number() OVER (ORDER BY timestamp, id) AS rn FROM evidence) s
        WHERE evidence.id = s.id
        """
    )
    op.alter_column("evidence", "sequence", nullable=False)
    op.create_index("ix_evidence_sequence", "evidence", ["sequence"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_evidence_sequence", table_name="evidence")
    op.drop_column("evidence", "sequence")
