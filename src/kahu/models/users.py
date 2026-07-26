"""User model for authentication."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from kahu.models.base import Base, TimestampMixin, UUIDPrimaryKey


class User(Base, UUIDPrimaryKey, TimestampMixin):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # admin, analyst, readonly
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
