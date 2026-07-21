"""Tickets — confirmed alerts that need resolution."""

import enum
import uuid
from typing import Optional

from sqlalchemy import Enum as SAEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class TicketStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class Ticket(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "tickets"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id"), unique=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[TicketStatus] = mapped_column(
        SAEnum(TicketStatus, name="ticket_status"),
        default=TicketStatus.OPEN,
    )
    assigned_to: Mapped[str] = mapped_column(String(255))
    closed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    alert: Mapped["Alert"] = relationship()  # noqa: F821
