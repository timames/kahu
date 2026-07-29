"""Connector instances — configured log sources."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum as SAEnum, String, func
from sqlalchemy import JSON as JSONB  # JSON works on both Postgres and SQLite
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey

import enum


class ConnectorStatus(str, enum.Enum):
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
        SAEnum(ConnectorStatus, name="connector_status"),
        default=ConnectorStatus.PENDING,
    )
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    credentials: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_event_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    events_today: Mapped[int] = mapped_column(default=0)
    events_total: Mapped[int] = mapped_column(default=0)
    error_message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
