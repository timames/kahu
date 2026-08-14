"""Pono Score snapshot model — score history with per-component breakdown."""

from datetime import datetime

from sqlalchemy import JSON as JSONB
from sqlalchemy import DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, UUIDPrimaryKey


class PonoSnapshot(Base, UUIDPrimaryKey):
    __tablename__ = "pono_snapshots"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    pono_score: Mapped[float] = mapped_column(Float, index=True)
    schema_version: Mapped[str] = mapped_column(String(20))
    components: Mapped[list] = mapped_column(JSONB)  # list of component result dicts
    biggest_gain: Mapped[dict | None] = mapped_column(JSONB)
    pono_drop: Mapped[dict | None] = mapped_column(JSONB)
    trigger: Mapped[str] = mapped_column(String(50))  # "scheduled", "manual", "event"
