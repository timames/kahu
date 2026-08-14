"""Connector instances — configured log sources."""

import enum
from datetime import datetime

from sqlalchemy import JSON as JSONB  # JSON works on both Postgres and SQLite
from sqlalchemy import DateTime, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ConnectorStatus(enum.StrEnum):
    PENDING = "pending"
    TESTING = "testing"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class ConnectorInstance(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "connector_instances"

    connector_type: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128))
    status: Mapped[ConnectorStatus] = mapped_column(
        SAEnum(ConnectorStatus, name="connector_status",
               values_callable=lambda x: [e.value for e in x]),
        default=ConnectorStatus.PENDING,
    )
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    credentials: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events_today: Mapped[int] = mapped_column(default=0)
    events_total: Mapped[int] = mapped_column(default=0)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
