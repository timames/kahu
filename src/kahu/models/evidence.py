"""Evidence store model — append-only, hash-chained compliance evidence."""

from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, UUIDPrimaryKey


class EvidenceRecord(Base, UUIDPrimaryKey):
    __tablename__ = "evidence"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    control_tags: Mapped[list] = mapped_column(JSONB)
    payload: Mapped[dict] = mapped_column(JSONB)
    actor: Mapped[str | None] = mapped_column(String(255))
    previous_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64), unique=True)
