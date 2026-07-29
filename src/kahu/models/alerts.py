"""Alert and disposition models — triage pipeline state."""

import enum
import uuid

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy import JSON as JSONB  # JSON works on both Postgres and SQLite
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DispositionVerdict(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"  # legacy — maps to ACKNOWLEDGED
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    UNDETERMINED = "undetermined"


class Alert(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "alerts"

    wazuh_alert_id: Mapped[str] = mapped_column(String(255), index=True)
    rule_id: Mapped[str] = mapped_column(String(50))
    rule_description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, values_callable=lambda x: [e.value for e in x]))
    agent_name: Mapped[str | None] = mapped_column(String(255))
    raw_event: Mapped[dict] = mapped_column(JSONB)
    enrichment: Mapped[dict | None] = mapped_column(JSONB)
    llm_triage: Mapped[dict | None] = mapped_column(JSONB)
    pipeline_provenance: Mapped[dict | None] = mapped_column(JSONB)
    control_tags: Mapped[list | None] = mapped_column(JSONB)

    disposition: Mapped["AlertDisposition | None"] = relationship(back_populates="alert")


class AlertDisposition(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "alert_dispositions"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id"), unique=True)
    verdict: Mapped[DispositionVerdict] = mapped_column(Enum(DispositionVerdict, values_callable=lambda x: [e.value for e in x]))
    analyst: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)

    alert: Mapped[Alert] = relationship(back_populates="disposition")
