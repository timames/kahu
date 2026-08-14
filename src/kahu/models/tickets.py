"""Tickets — confirmed alerts that need resolution."""

import enum
import uuid

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class TicketStatus(enum.StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class TicketType(enum.StrEnum):
    INCIDENT = "incident"  # Confirmed true positive — respond & remediate
    INVESTIGATION = "investigation"  # Escalated — needs deeper analysis first


class Ticket(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "tickets"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id"), unique=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(20))
    ticket_type: Mapped[str | None] = mapped_column(
        String(20),
        default=TicketType.INCIDENT.value,
        nullable=True,
    )
    status: Mapped[TicketStatus] = mapped_column(
        SAEnum(TicketStatus, name="ticket_status"),
        default=TicketStatus.OPEN,
    )
    assigned_to: Mapped[str] = mapped_column(String(255))
    closed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    alert: Mapped["Alert"] = relationship()  # noqa: F821
