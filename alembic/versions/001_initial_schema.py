"""Initial schema — all tables.

Revision ID: 001
Revises:
Create Date: 2026-07-25

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001"
down_revision = None
branch_labels = None
depends_on = None

# Postgres enum types matching the Python StrEnum definitions in models/.
severity_enum = postgresql.ENUM(
    "critical", "high", "medium", "low", "info",
    name="severity", create_type=False,
)
verdict_enum = postgresql.ENUM(
    "true_positive", "acknowledged", "false_positive", "benign_true_positive", "undetermined",
    name="dispositionverdict", create_type=False,
)
connector_status_enum = postgresql.ENUM(
    "pending", "testing", "active", "error", "disabled",
    name="connector_status", create_type=False,
)
ticket_status_enum = postgresql.ENUM(
    "open", "in_progress", "closed",
    name="ticket_status", create_type=False,
)
validation_verdict_enum = postgresql.ENUM(
    "pass", "fail", "unreachable", "pending",
    name="validation_verdict", create_type=False,
)


def upgrade() -> None:
    # Create Postgres enum types first
    severity_enum.create(op.get_bind(), checkfirst=True)
    verdict_enum.create(op.get_bind(), checkfirst=True)
    connector_status_enum.create(op.get_bind(), checkfirst=True)
    ticket_status_enum.create(op.get_bind(), checkfirst=True)
    validation_verdict_enum.create(op.get_bind(), checkfirst=True)

    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Alerts
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("wazuh_alert_id", sa.String(255), nullable=False, index=True),
        sa.Column("rule_id", sa.String(50), nullable=False),
        sa.Column("rule_description", sa.Text(), nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("agent_name", sa.String(255), nullable=True),
        sa.Column("raw_event", postgresql.JSONB(), nullable=False),
        sa.Column("enrichment", postgresql.JSONB(), nullable=True),
        sa.Column("llm_triage", postgresql.JSONB(), nullable=True),
        sa.Column("pipeline_provenance", postgresql.JSONB(), nullable=True),
        sa.Column("control_tags", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Alert dispositions
    op.create_table(
        "alert_dispositions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id"), nullable=False, unique=True),
        sa.Column("verdict", verdict_enum, nullable=False),
        sa.Column("analyst", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Evidence (append-only, hash-chained)
    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True),
        sa.Column("event_type", sa.String(100), nullable=False, index=True),
        sa.Column("control_tags", postgresql.JSONB(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False, unique=True),
    )

    # Compliance profiles
    op.create_table(
        "compliance_profiles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("framework_id", sa.String(100), nullable=False, unique=True),
        sa.Column("framework_name", sa.String(255), nullable=False),
        sa.Column("organization_name", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(500), nullable=False, server_default="All systems"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("control_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Connector instances
    op.create_table(
        "connector_instances",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connector_type", sa.String(64), nullable=False, index=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("status", connector_status_enum, nullable=False, server_default="pending"),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("credentials", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("events_today", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("events_total", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Tickets
    op.create_table(
        "tickets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id"), nullable=False, unique=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("ticket_type", sa.String(20), nullable=True, server_default="incident"),
        sa.Column("status", ticket_status_enum, nullable=False, server_default="open"),
        sa.Column("assigned_to", sa.String(255), nullable=False),
        sa.Column("closed_by", sa.String(255), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # XP events (gamification)
    op.create_table(
        "xp_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("analyst", sa.String(255), nullable=False, index=True),
        sa.Column("points", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("ref_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # Pono Score snapshots
    op.create_table(
        "pono_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True),
        sa.Column("pono_score", sa.Float(), nullable=False, index=True),
        sa.Column("schema_version", sa.String(20), nullable=False),
        sa.Column("components", postgresql.JSONB(), nullable=False),
        sa.Column("biggest_gain", postgresql.JSONB(), nullable=True),
        sa.Column("pono_drop", postgresql.JSONB(), nullable=True),
        sa.Column("trigger", sa.String(50), nullable=False),
    )

    # Validation samples
    op.create_table(
        "validation_samples",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("round_id", sa.String(36), nullable=False, index=True),
        sa.Column("agent_id", sa.String(255), nullable=False, index=True),
        sa.Column("agent_name", sa.String(255), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verdict", validation_verdict_enum, nullable=False, server_default="pending"),
        sa.Column("checks", postgresql.JSONB(), nullable=True),
        sa.Column("findings", postgresql.JSONB(), nullable=True),
        sa.Column("score_at_sample", sa.Float(), nullable=True),
    )

    # Validation rounds
    op.create_table(
        "validation_rounds",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("fleet_size", sa.Integer(), nullable=False),
        sa.Column("samples_completed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("samples_passed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("samples_failed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("samples_unreachable", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("pono_score_at_start", sa.Float(), nullable=False),
        sa.Column("validation_rate", sa.Float(), nullable=True),
        sa.Column("drift_detected", sa.Boolean(), nullable=True),
        sa.Column("summary", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("validation_rounds")
    op.drop_table("validation_samples")
    op.drop_table("pono_snapshots")
    op.drop_table("xp_events")
    op.drop_table("tickets")
    op.drop_table("connector_instances")
    op.drop_table("compliance_profiles")
    op.drop_table("evidence")
    op.drop_table("alert_dispositions")
    op.drop_table("alerts")
    op.drop_table("users")

    # Drop enum types
    validation_verdict_enum.drop(op.get_bind(), checkfirst=True)
    ticket_status_enum.drop(op.get_bind(), checkfirst=True)
    connector_status_enum.drop(op.get_bind(), checkfirst=True)
    verdict_enum.drop(op.get_bind(), checkfirst=True)
    severity_enum.drop(op.get_bind(), checkfirst=True)
