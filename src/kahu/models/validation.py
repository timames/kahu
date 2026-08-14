"""Validation sample models — random endpoint spot-checks against the Pono Score."""

import enum
from datetime import datetime

from sqlalchemy import JSON as JSONB
from sqlalchemy import DateTime, Float, Integer, String, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, UUIDPrimaryKey


class ValidationVerdict(enum.StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    UNREACHABLE = "unreachable"
    PENDING = "pending"


class ValidationSample(Base, UUIDPrimaryKey):
    """A single endpoint spot-check within a validation round."""

    __tablename__ = "validation_samples"

    round_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    agent_name: Mapped[str] = mapped_column(String(255))
    scheduled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verdict: Mapped[ValidationVerdict] = mapped_column(
        SAEnum(ValidationVerdict, name="validation_verdict"),
        default=ValidationVerdict.PENDING,
    )
    checks: Mapped[dict | None] = mapped_column(JSONB)
    findings: Mapped[list | None] = mapped_column(JSONB)
    score_at_sample: Mapped[float | None] = mapped_column(Float, nullable=True)


class ValidationRound(Base, UUIDPrimaryKey):
    """A monthly validation round — selects N endpoints, runs checks, compares to score."""

    __tablename__ = "validation_rounds"

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sample_size: Mapped[int] = mapped_column(Integer)
    fleet_size: Mapped[int] = mapped_column(Integer)
    samples_completed: Mapped[int] = mapped_column(Integer, default=0)
    samples_passed: Mapped[int] = mapped_column(Integer, default=0)
    samples_failed: Mapped[int] = mapped_column(Integer, default=0)
    samples_unreachable: Mapped[int] = mapped_column(Integer, default=0)
    pono_score_at_start: Mapped[float] = mapped_column(Float)
    validation_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    drift_detected: Mapped[bool | None] = mapped_column(nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSONB)
