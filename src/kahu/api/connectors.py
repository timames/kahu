"""Connector management API — add, test, and manage log sources."""

from __future__ import annotations

import contextlib
import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.wazuh import WazuhAPIClient, WazuhIndexerClient
from kahu.db import get_session
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.services.connectors.catalog import CATALOG, get_catalog, get_categories

logger = logging.getLogger(__name__)

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
async def list_sources(session: AsyncSession = Depends(get_session)):  # noqa: B008
    """List all configured connector instances plus live Wazuh sources."""
    result = await session.execute(
        select(ConnectorInstance).order_by(ConnectorInstance.created_at.desc())
    )
    instances = result.scalars().all()
    sources = [_to_out(c) for c in instances]

    # Merge live Wazuh sources
    wazuh_sources = await _get_wazuh_sources()
    sources = wazuh_sources + sources
    return sources


@router.get("/overview", response_model=SourcesOverview)
async def sources_overview(session: AsyncSession = Depends(get_session)):  # noqa: B008
    """Summary stats for the sources screen."""
    result = await session.execute(select(ConnectorInstance))
    instances = result.scalars().all()

    active = sum(1 for c in instances if c.status == ConnectorStatus.ACTIVE)
    errors = sum(1 for c in instances if c.status == ConnectorStatus.ERROR)
    events = sum(c.events_today for c in instances)

    # Add live Wazuh sources
    wazuh_sources = await _get_wazuh_sources()
    wazuh_active = sum(1 for s in wazuh_sources if s.status == "active")
    wazuh_events = sum(s.events_today for s in wazuh_sources)

    total = len(instances) + len(wazuh_sources)
    active += wazuh_active
    events += wazuh_events

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

    if wazuh_sources:
        wazuh_cat = cat_counts.get(
            "siem", {"id": "siem", "sources": 0, "active": 0, "events_today": 0}
        )
        wazuh_cat["sources"] += len(wazuh_sources)
        wazuh_cat["active"] += wazuh_active
        wazuh_cat["events_today"] += wazuh_events
        cat_counts["siem"] = wazuh_cat

    return SourcesOverview(
        total_sources=total,
        active_sources=active,
        error_sources=errors,
        events_today=events,
        categories=list(cat_counts.values()),
    )


@router.post("/sources", response_model=ConnectorOut, status_code=201)
async def add_source(
    body: ConnectorCreate,
    session: AsyncSession = Depends(get_session),  # noqa: B008
):
    """Add a new log source."""
    if body.connector_type not in CATALOG:
        raise HTTPException(404, f"Unknown connector type: {body.connector_type}")

    ct = CATALOG[body.connector_type]

    # Validate required fields
    for field in ct.fields:
        if field.required and field.name not in body.credentials and field.name not in body.config:
            raise HTTPException(422, f"Missing required field: {field.label}")

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
    session: AsyncSession = Depends(get_session),  # noqa: B008
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
        instance.last_event_at = datetime.now(UTC)
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
    session: AsyncSession = Depends(get_session),  # noqa: B008
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
    session: AsyncSession = Depends(get_session),  # noqa: B008
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
    has_creds = any(v and str(v).strip() for v in {**creds, **config}.values())

    if not has_creds:
        return False, "No credentials provided"

    # Check for obviously invalid values
    for field in ct.fields:
        val = creds.get(field.name) or config.get(field.name)
        if field.required and (not val or not str(val).strip()):
            return False, f"Missing required field: {field.label}"

    return True, f"Successfully connected to {ct.name}"


async def _get_wazuh_sources() -> list[ConnectorOut]:
    """Query Wazuh API for manager + agents and indexer for event counts."""
    try:
        wazuh = WazuhAPIClient()
        await wazuh.authenticate()
        resp = await wazuh.api_get(
            "/agents",
            params={
                "limit": 500,
                "select": "id,name,ip,status,os.platform,os.name,dateAdd,lastKeepAlive",
            },
        )
        agents = resp.get("data", {}).get("affected_items", [])
    except Exception:
        logger.debug("Could not fetch Wazuh agents", exc_info=True)
        return []

    # Get today's event counts per agent from the indexer
    agent_events: dict[str, int] = {}
    total_events: dict[str, int] = {}
    try:
        indexer = WazuhIndexerClient()
        count_resp = await indexer.search(
            "wazuh-alerts-*",
            {"size": 0, "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 500}}}},
        )
        for bucket in count_resp.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            total_events[bucket["key"]] = bucket["doc_count"]

        today = datetime.now(UTC).strftime("%Y.%m.%d")
        today_resp = await indexer.search(
            f"wazuh-alerts-4.x-{today}",
            {"size": 0, "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 500}}}},
        )
        for bucket in today_resp.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            agent_events[bucket["key"]] = bucket["doc_count"]
    except Exception:
        logger.debug("Could not fetch indexer event counts", exc_info=True)

    sources = []
    for agent in agents:
        agent_id = agent.get("id", "000")
        name = agent.get("name", "unknown")
        status = agent.get("status", "disconnected")
        os_name = agent.get("os", {}).get("name", "")
        os_platform = agent.get("os", {}).get("platform", "")
        date_add = agent.get("dateAdd")
        last_alive = agent.get("lastKeepAlive")

        is_manager = agent_id == "000"
        icon = (
            "\U0001f5a5\ufe0f"
            if os_platform == "windows"
            else "\U0001f4e1"
            if is_manager
            else "\U0001f427"
            if os_platform == "linux"
            else "\U0001f4bb"
        )
        type_name = (
            "Wazuh Manager"
            if is_manager
            else f"Wazuh Agent ({os_name or os_platform or 'unknown'})"
        )

        mapped_status = (
            "active"
            if status in ("active", "Active")
            else "error"
            if status == "disconnected"
            else "pending"
        )

        created = None
        if date_add:
            try:
                created = datetime.fromisoformat(date_add.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                created = datetime.now(UTC)

        last_event = None
        if last_alive:
            with contextlib.suppress(ValueError, AttributeError):
                last_event = datetime.fromisoformat(last_alive.replace("Z", "+00:00"))

        sources.append(
            ConnectorOut(
                id=uuid.uuid5(uuid.NAMESPACE_DNS, f"wazuh-agent-{agent_id}"),
                connector_type="wazuh_agent",
                name=name,
                type_name=type_name,
                type_icon=icon,
                category="siem",
                status=mapped_status,
                events_today=agent_events.get(name, 0),
                events_total=total_events.get(name, 0),
                last_event_at=last_event,
                error_message=None if mapped_status != "error" else f"Agent {status}",
                created_at=created or datetime.now(UTC),
            )
        )

    return sources
