"""XP ledger — append-only log of points earned."""

import uuid
from typing import Optional

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class XpEvent(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "xp_events"

    analyst: Mapped[str] = mapped_column(String(255), index=True)
    points: Mapped[int] = mapped_column()
    reason: Mapped[str] = mapped_column(String(255))
    ref_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
