"""Vulnerability scan and finding models — persistent storage."""

import enum
import uuid

from sqlalchemy import Enum, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kuahene.models.base import Base, TimestampMixin, UUIDPrimaryKey


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class VulnScan(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "vuln_scans"

    scan_type: Mapped[str] = mapped_column(String(50))
    targets: Mapped[list] = mapped_column(JSONB, default=list)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, values_callable=lambda x: [e.value for e in x]),
        default=ScanStatus.PENDING,
    )
    finding_count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class VulnFinding(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "vuln_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column()
    severity: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    affected_host: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, values_callable=lambda x: [e.value for e in x]),
        default=FindingStatus.OPEN,
    )
    source: Mapped[str] = mapped_column(String(50), default="wazuh")
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
