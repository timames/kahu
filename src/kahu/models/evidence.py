"""Evidence store model — append-only, hash-chained compliance evidence."""

from datetime import datetime

from sqlalchemy import JSON as JSONB  # JSON works on both Postgres and SQLite
from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, UUIDPrimaryKey


class EvidenceRecord(Base, UUIDPrimaryKey):
    __tablename__ = "evidence"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # Monotonic chain position, assigned in record_evidence() under an
    # append lock. `timestamp` is NOT a total order — concurrent transactions
    # share now() values, which is how the chain historically forked.
    sequence: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    control_tags: Mapped[list] = mapped_column(JSONB)
    payload: Mapped[dict] = mapped_column(JSONB)
    actor: Mapped[str | None] = mapped_column(String(255))
    previous_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64), unique=True)
