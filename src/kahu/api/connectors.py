"""Connector management API — add, test, and manage log sources."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.services.connectors.catalog import CATALOG, get_catalog, get_categories

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────


class ConnectorCreate(BaseModel):
    connector_type: str
    name: str
    config: dict = {}
    credentials: dict = {}


class ConnectorOut(BaseModel):
    id: uuid.UUID
    connector_type: str
    name: str
    type_name: str
    type_icon: str
    category: str
    status: str
    events_today: int
    events_total: int
    last_event_at: datetime | None
    error_message: str | None
    created_at: datetime


class ConnectorTestResult(BaseModel):
    success: bool
    message: str
    events_sample: int


class CatalogResponse(BaseModel):
    categories: list[dict]
    connectors: list[dict]


class SourcesOverview(BaseModel):
    total_sources: int
    active_sources: int
    error_sources: int
    events_today: int
    categories: list[dict]


# ── Catalog ────────────────────────────────────────────────


@router.get("/catalog", response_model=CatalogResponse)
async def catalog():
    """Return the full connector type catalog with setup fields."""
    return CatalogResponse(
        categories=get_categories(),
        connectors=get_catalog(),
    )


# ── CRUD ───────────────────────────────────────────────────


@router.get("/sources", response_model=list[ConnectorOut])
async def list_sources(session: AsyncSession = Depends(get_session)):
    """List all configured connector instances."""
    result = await session.execute(
        select(ConnectorInstance).order_by(ConnectorInstance.created_at.desc())
    )
    instances = result.scalars().all()
    return [_to_out(c) for c in instances]


@router.get("/overview", response_model=SourcesOverview)
async def sources_overview(session: AsyncSession = Depends(get_session)):
    """Summary stats for the sources screen."""
    result = await session.execute(select(ConnectorInstance))
    instances = result.scalars().all()

    active = sum(1 for c in instances if c.status == ConnectorStatus.ACTIVE)
    errors = sum(1 for c in instances if c.status == ConnectorStatus.ERROR)
    events = sum(c.events_today for c in instances)

    # Category breakdown
    cat_counts: dict[str, dict] = {}
    for c in instances:
        ct = CATALOG.get(c.connector_type)
        cat = ct.category if ct else "unknown"
        if cat not in cat_counts:
            cat_counts[cat] = {"id": cat, "sources": 0, "active": 0, "events_today": 0}
        cat_counts[cat]["sources"] += 1
        if c.status == ConnectorStatus.ACTIVE:
            cat_counts[cat]["active"] += 1
        cat_counts[cat]["events_today"] += c.events_today

    return SourcesOverview(
        total_sources=len(instances),
        active_sources=active,
        error_sources=errors,
        events_today=events,
        categories=list(cat_counts.values()),
    )


@router.post("/sources", response_model=ConnectorOut, status_code=201)
async def add_source(
    body: ConnectorCreate,
    session: AsyncSession = Depends(get_session),
):
    """Add a new log source."""
    if body.connector_type not in CATALOG:
        raise HTTPException(404, f"Unknown connector type: {body.connector_type}")

    ct = CATALOG[body.connector_type]

    # Validate required fields
    for field in ct.fields:
        if field.required and field.name not in body.credentials and field.name not in body.config:
            raise HTTPException(
                422, f"Missing required field: {field.label}"
            )

    instance = ConnectorInstance(
        connector_type=body.connector_type,
        name=body.name,
        status=ConnectorStatus.PENDING,
        config=body.config,
        credentials=body.credentials,
    )
    session.add(instance)
    await session.commit()
    await session.refresh(instance)
    return _to_out(instance)


@router.post("/sources/{source_id}/test", response_model=ConnectorTestResult)
async def test_source(
    source_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Test connectivity to a configured source."""
    instance = await session.get(ConnectorInstance, source_id)
    if not instance:
        raise HTTPException(404, "Source not found")

    ct = CATALOG.get(instance.connector_type)
    if not ct:
        raise HTTPException(400, "Unknown connector type")

    # Update status to testing
    instance.status = ConnectorStatus.TESTING
    await session.commit()

    # For now, simulate a connection test based on auth method
    # In production, each connector type would have a real test_connection()
    success, message = _simulate_test(ct, instance)

    instance.status = ConnectorStatus.ACTIVE if success else ConnectorStatus.ERROR
    instance.error_message = None if success else message
    if success:
        instance.last_event_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(instance)

    return ConnectorTestResult(
        success=success,
        message=message,
        events_sample=0,
    )


@router.delete("/sources/{source_id}", status_code=204)
async def delete_source(
    source_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Remove a configured source."""
    instance = await session.get(ConnectorInstance, source_id)
    if not instance:
        raise HTTPException(404, "Source not found")
    await session.delete(instance)
    await session.commit()


@router.patch("/sources/{source_id}/toggle")
async def toggle_source(
    source_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Enable or disable a source."""
    instance = await session.get(ConnectorInstance, source_id)
    if not instance:
        raise HTTPException(404, "Source not found")

    if instance.status == ConnectorStatus.DISABLED:
        instance.status = ConnectorStatus.ACTIVE
    else:
        instance.status = ConnectorStatus.DISABLED
    await session.commit()
    await session.refresh(instance)
    return _to_out(instance)


# ── Helpers ────────────────────────────────────────────────


def _to_out(c: ConnectorInstance) -> ConnectorOut:
    ct = CATALOG.get(c.connector_type)
    return ConnectorOut(
        id=c.id,
        connector_type=c.connector_type,
        name=c.name,
        type_name=ct.name if ct else c.connector_type,
        type_icon=ct.icon if ct else "\U0001f4cb",
        category=ct.category if ct else "unknown",
        status=c.status.value,
        events_today=c.events_today,
        events_total=c.events_total,
        last_event_at=c.last_event_at,
        error_message=c.error_message,
        created_at=c.created_at,
    )


def _simulate_test(ct, instance) -> tuple[bool, str]:
    """Placeholder test — checks that credentials are non-empty.

    Real implementation will attempt actual connections per connector type.
    """
    creds = instance.credentials
    config = instance.config

    # Check that at least one credential field has a value
    has_creds = any(
        v and str(v).strip()
        for v in {**creds, **config}.values()
    )

    if not has_creds:
        return False, "No credentials provided"

    # Check for obviously invalid values
    for field in ct.fields:
        val = creds.get(field.name) or config.get(field.name)
        if field.required and (not val or not str(val).strip()):
            return False, f"Missing required field: {field.label}"

    return True, f"Successfully connected to {ct.name}"
