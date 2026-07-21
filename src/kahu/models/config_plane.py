"""Config-plane models — token enrollment, sessions, audit, scope, licensing, resets."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text  # noqa: F401
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


# ── Enums ────────────────────────────────────────────────────────────────

class TokenType(str, enum.Enum):
    YUBIKEY = "yubikey"
    ENCRYPTED_USB = "encrypted_usb"
    SOFTWARE_DEV = "software_dev"


class TokenStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class SessionStatus(str, enum.Enum):
    ACTIVE = "active"
    CLOSED = "closed"
    FORCE_CLOSED = "force_closed"


class ScopeStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class LicenseTier(str, enum.Enum):
    SELF_ASSESSMENT = "self_assessment"
    PRACTITIONER = "practitioner"


class LicenseStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class ResetType(str, enum.Enum):
    FULL = "full"
    DATA_ONLY = "data_only"


# ── Models ───────────────────────────────────────────────────────────────

class TokenEnrollment(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "token_enrollments"

    token_serial: Mapped[str] = mapped_column(String(255), unique=True)
    token_type: Mapped[TokenType] = mapped_column(
        Enum(TokenType, values_callable=lambda x: [e.value for e in x])
    )
    enrolled_by: Mapped[str] = mapped_column(String(255))
    status: Mapped[TokenStatus] = mapped_column(
        Enum(TokenStatus, values_callable=lambda x: [e.value for e in x]),
        default=TokenStatus.ACTIVE,
    )
    public_key_fingerprint: Mapped[str] = mapped_column(String(255))

    sessions: Mapped[list["ConfigPlaneSession"]] = relationship(back_populates="token")


class ConfigPlaneSession(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "config_plane_sessions"

    token_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("token_enrollments.id"))
    operator: Mapped[str] = mapped_column(String(255))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus, values_callable=lambda x: [e.value for e in x]),
        default=SessionStatus.ACTIVE,
    )

    token: Mapped[TokenEnrollment] = relationship(back_populates="sessions")
    changes: Mapped[list["ConfigChangeLog"]] = relationship(back_populates="session")


class ConfigChangeLog(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "config_change_logs"

    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("config_plane_sessions.id"))
    operator: Mapped[str] = mapped_column(String(255))
    prompt_text: Mapped[str] = mapped_column(Text)
    diff_json: Mapped[dict] = mapped_column(JSONB)
    artifact_type: Mapped[str] = mapped_column(String(255))
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    session: Mapped[ConfigPlaneSession] = relationship(back_populates="changes")


class AssessmentScope(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "assessment_scopes"

    name: Mapped[str] = mapped_column(String(255))
    cidrs: Mapped[list] = mapped_column(JSONB, default=list)
    hosts: Mapped[list] = mapped_column(JSONB, default=list)
    exclusions: Mapped[list] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[ScopeStatus] = mapped_column(
        Enum(ScopeStatus, values_callable=lambda x: [e.value for e in x]),
        default=ScopeStatus.ACTIVE,
    )


class PractitionerLicense(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "practitioner_licenses"

    license_key: Mapped[str] = mapped_column(String(255), unique=True)
    operator_name: Mapped[str] = mapped_column(String(255))
    organization: Mapped[str] = mapped_column(String(255))
    tier: Mapped[LicenseTier] = mapped_column(
        Enum(LicenseTier, values_callable=lambda x: [e.value for e in x])
    )
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[LicenseStatus] = mapped_column(
        Enum(LicenseStatus, values_callable=lambda x: [e.value for e in x]),
        default=LicenseStatus.ACTIVE,
    )


class FactoryResetLog(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "factory_reset_logs"

    initiated_by: Mapped[str] = mapped_column(String(255))
    reset_type: Mapped[ResetType] = mapped_column(
        Enum(ResetType, values_callable=lambda x: [e.value for e in x])
    )
    attestation_hash: Mapped[str] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
