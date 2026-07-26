"""Auth API — login, token refresh, setup (first user), and user management."""

from __future__ import annotations

from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.api.deps import get_current_user, require_role
from kahu.models.users import User
from kahu.services.auth import (
    create_access_token,
    create_refresh_token,
    create_user,
    decode_token,
    get_user_by_id,
    get_user_by_username,
    user_count,
    verify_password,
)

router = APIRouter()


# ── Request / Response schemas ──


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    username: str
    role: str


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst|readonly)$")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool


# ── Endpoints ──


@router.get("/setup-required")
async def setup_required(session: AsyncSession = Depends(get_session)) -> dict:
    """Check whether the appliance needs initial setup (no users exist yet)."""
    count = await user_count(session)
    return {"setup_required": count == 0}


@router.post("/setup", response_model=TokenResponse)
async def setup(body: SetupRequest, session: AsyncSession = Depends(get_session)):
    """Create the first admin user. Only works when no users exist."""
    count = await user_count(session)
    if count > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup already completed")

    user = await create_user(session, body.username, body.email, body.password, role="admin")
    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role),
        refresh_token=create_refresh_token(user.id),
        username=user.username,
        role=user.role,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    user = await get_user_by_username(session, body.username)
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role),
        refresh_token=create_refresh_token(user.id),
        username=user.username,
        role=user.role,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, session: AsyncSession = Depends(get_session)):
    try:
        payload = decode_token(body.refresh_token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not a refresh token")

    user = await get_user_by_id(session, UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    return TokenResponse(
        access_token=create_access_token(user.id, user.username, user.role),
        refresh_token=create_refresh_token(user.id),
        username=user.username,
        role=user.role,
    )


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
    )


@router.post("/users", response_model=UserResponse)
async def create_new_user(
    body: CreateUserRequest,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_role("admin")),
):
    """Create a new user (admin only)."""
    existing = await get_user_by_username(session, body.username)
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")

    user = await create_user(session, body.username, body.email, body.password, body.role)
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
    )
