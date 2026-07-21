"""Compliance profile model — persistent activated framework profiles."""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ComplianceProfile(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "compliance_profiles"

    framework_id: Mapped[str] = mapped_column(String(100), unique=True)
    framework_name: Mapped[str] = mapped_column(String(255))
    organization_name: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(Text, default="All systems")
    status: Mapped[str] = mapped_column(String(50), default="active")
    control_count: Mapped[int] = mapped_column(default=0)
