"""Connector instance model — declared state for source onboarding."""

import enum

from sqlalchemy import Enum, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ConnectorStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    ERROR = "error"


class ConnectorInstance(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "connector_instances"

    connector_type: Mapped[str] = mapped_column(String(100), index=True)
    name: Mapped[str] = mapped_column(String(255))
    status: Mapped[ConnectorStatus] = mapped_column(Enum(ConnectorStatus, values_callable=lambda x: [e.value for e in x]))
    config: Mapped[dict] = mapped_column(JSONB)
    control_tags: Mapped[list] = mapped_column(JSONB)
    last_event_at: Mapped[str | None] = mapped_column(Text)
