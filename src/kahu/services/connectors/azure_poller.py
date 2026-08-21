"""Native Kahu poller for Microsoft Azure / Defender / Entra connectors.

One background loop serves every ACTIVE instance of the three Azure connector
types. Each instance is polled independently inside its own try/except, so a
tenant with a revoked secret cannot block ingestion for the others.

Cursor discipline (fixes the Wazuh poller's in-memory-cursor anti-pattern):
the poll position lives in ``ConnectorInstance.cursor`` (JSONB) and is only
advanced after a successful pipeline run + commit, so a restart resumes where
ingestion actually left off — no skipped backlog, no re-drain. First run
starts at now-15m so a freshly added connector doesn't drain tenant history
through the LLM-serialized pipeline.

Dedup is three layers deep:
1. Server-side ``createdDateTime ge <watermark>`` (createdDateTime, never
   lastUpdateDateTime — updates churn and would re-ingest).
2. The ``seen_ids`` ring (last 500) absorbs the inclusive ``ge`` boundary.
3. A batch DB pre-check on ``Alert.wazuh_alert_id`` (ids are prefixed
   ``defender:``/``entra:``/``la:`` so they can never collide with Wazuh ids).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.azure import AzureAuthError, AzureClient, la_rows_as_dicts
from kahu.clients.ollama import OllamaClient
from kahu.db import async_session
from kahu.models.alerts import Alert
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.services.connectors.azure_transform import (
    signin_matches_filter,
    transform_defender_alert,
    transform_entra_signin,
    transform_la_row,
)
from kahu.services.triage.pipeline import run_pipeline_batch

log = logging.getLogger("kahu.azure_poller")

AZURE_CONNECTOR_TYPES = ("microsoft_defender", "azure_log_analytics", "entra_signin")

# Per-instance, per-cycle ingest cap. The triage pipeline is LLM-serialized;
# anything beyond the cap stays behind the watermark and drains next cycle.
MAX_EVENTS_PER_CYCLE = 200

SEEN_IDS_MAX = 500

FIRST_RUN_LOOKBACK = timedelta(minutes=15)

# Entra sign-in ingestion lags several minutes; polling right up to "now"
# would permanently skip late-arriving entries once the watermark passes them.
ENTRA_INGESTION_LAG = timedelta(minutes=5)

_MAP_DEFAULT_LEVELS = {"5": 5, "7": 7, "10": 10, "12": 12}


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_client(instance: ConnectorInstance) -> AzureClient:
    cfg = {**(instance.config or {}), **(instance.credentials or {})}
    return AzureClient(
        tenant_id=str(cfg.get("tenant_id", "")),
        client_id=str(cfg.get("client_id", "")),
        client_secret=str(cfg.get("client_secret", "")),
        cloud=str(cfg.get("cloud_environment") or "commercial"),
    )


# ── Per-type fetchers: return Wazuh-shaped events ─────────


async def _fetch_defender(
    client: AzureClient, cfg: dict[str, Any], watermark: str
) -> list[dict[str, Any]]:
    alerts = await client.graph_get(
        "/v1.0/security/alerts_v2",
        params={
            "$filter": f"createdDateTime ge {watermark}",
            "$orderby": "createdDateTime asc",
            "$top": 100,
        },
        max_items=MAX_EVENTS_PER_CYCLE,
    )
    return [transform_defender_alert(a) for a in alerts]


async def _fetch_entra(
    client: AzureClient, cfg: dict[str, Any], watermark: str
) -> list[dict[str, Any]]:
    lag_end = _iso(datetime.now(UTC) - ENTRA_INGESTION_LAG)
    if watermark >= lag_end:
        return []
    signins = await client.graph_get(
        "/v1.0/auditLogs/signIns",
        params={
            "$filter": (f"createdDateTime ge {watermark} and createdDateTime le {lag_end}"),
            "$orderby": "createdDateTime asc",
            "$top": 100,
        },
        max_items=MAX_EVENTS_PER_CYCLE,
    )
    # Risk/failure predicate is client-side: errorCode/riskLevel OData filters
    # are unreliable app-only, so the server filter is time-only.
    mode = str(cfg.get("signin_filter") or "risky_or_failed")
    return [transform_entra_signin(s) for s in signins if signin_matches_filter(s, mode)]


async def _fetch_log_analytics(
    client: AzureClient, cfg: dict[str, Any], watermark: str
) -> list[dict[str, Any]]:
    workspace_id = str(cfg.get("workspace_id", ""))
    kql = str(cfg.get("kql_query", ""))
    if not workspace_id or not kql.strip():
        return []
    default_level = _MAP_DEFAULT_LEVELS.get(str(cfg.get("default_level", "7")), 7)
    resp = await client.la_query(
        workspace_id, kql, timespan=f"{watermark}/{_iso(datetime.now(UTC))}"
    )
    rows = la_rows_as_dicts(resp)[:MAX_EVENTS_PER_CYCLE]
    return [
        transform_la_row(
            row,
            workspace_id,
            query_name=str(cfg.get("query_name") or "Log Analytics query"),
            default_level=default_level,
        )
        for row in rows
    ]


_FETCHERS = {
    "microsoft_defender": _fetch_defender,
    "entra_signin": _fetch_entra,
    "azure_log_analytics": _fetch_log_analytics,
}


# ── Poll one instance ─────────────────────────────────────


async def _poll_instance(
    session: AsyncSession,
    instance: ConnectorInstance,
    client: AzureClient | None = None,
    ollama: OllamaClient | None = None,
) -> int:
    """Fetch, dedup, and ingest new events for one connector instance.

    Returns the number of events handed to the pipeline. Raises on fetch/auth
    failure — classification into ERROR vs transient happens in the caller.
    """
    client = client or _build_client(instance)
    cfg = {**(instance.config or {}), **(instance.credentials or {})}
    cursor = dict(instance.cursor or {})
    watermark = cursor.get("watermark") or _iso(datetime.now(UTC) - FIRST_RUN_LOOKBACK)
    seen_ids = list(cursor.get("seen_ids") or [])

    events = await _FETCHERS[instance.connector_type](client, cfg, watermark)

    # Advance the watermark over everything fetched (dups included) so the
    # `ge` window keeps moving even when every event is a repeat.
    new_watermark = watermark
    for ev in events:
        ts = ev.get("timestamp")
        if ts and ts > new_watermark:
            new_watermark = ts

    # Layer 2: seen-id ring (absorbs the inclusive `ge` boundary overlap).
    seen_set = set(seen_ids)
    fresh = [ev for ev in events if ev["id"] not in seen_set]

    # Layer 3: batch DB pre-check (survives seen_ids truncation/reset).
    if fresh:
        existing = set(
            (
                await session.execute(
                    select(Alert.wazuh_alert_id).where(
                        Alert.wazuh_alert_id.in_([ev["id"] for ev in fresh])
                    )
                )
            ).scalars()
        )
        fresh = [ev for ev in fresh if ev["id"] not in existing]

    if fresh:
        _, stats = await run_pipeline_batch(
            raw_alerts=fresh,
            session=session,
            indexer=None,
            ollama=ollama or OllamaClient(),
        )
        log.info(
            "azure_poller: %s (%s) processed=%d filtered=%d persisted=%d errors=%d",
            instance.name,
            instance.connector_type,
            stats.total,
            stats.filtered,
            stats.persisted,
            stats.errors,
        )

    # Successful poll: persist cursor + counters and clear any stale error.
    seen_ids.extend(ev["id"] for ev in fresh)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    today_count = cursor.get("today_count", 0) if cursor.get("today") == today else 0
    today_count += len(fresh)
    instance.cursor = {
        "watermark": new_watermark,
        "seen_ids": seen_ids[-SEEN_IDS_MAX:],
        "today": today,
        "today_count": today_count,
    }
    instance.events_total = (instance.events_total or 0) + len(fresh)
    instance.events_today = today_count
    if fresh:
        instance.last_event_at = datetime.now(UTC)
    instance.error_message = None
    instance.status = ConnectorStatus.ACTIVE
    await session.commit()
    return len(fresh)


# ── Poll cycle across all instances ───────────────────────


async def poll_all_azure_once() -> int:
    """One poll cycle over every ACTIVE Azure connector instance."""
    total = 0
    async with async_session() as session:
        # Iterate by id and re-get per instance: a failed instance's rollback
        # expires every object loaded in this session, and touching an expired
        # attribute in an async session is a sync lazy-load (greenlet error).
        instance_ids = list(
            (
                await session.execute(
                    select(ConnectorInstance.id).where(
                        ConnectorInstance.connector_type.in_(AZURE_CONNECTOR_TYPES),
                        ConnectorInstance.status == ConnectorStatus.ACTIVE,
                    )
                )
            ).scalars()
        )
        for instance_id in instance_ids:
            instance = await session.get(ConnectorInstance, instance_id)
            if instance is None:
                continue
            try:
                total += await _poll_instance(session, instance)
            except Exception as exc:
                await _record_poll_failure(session, instance, exc)
    return total


async def _record_poll_failure(
    session: AsyncSession, instance: ConnectorInstance, exc: Exception
) -> None:
    """Classify a poll failure: auth-class -> ERROR, transient -> message only."""
    try:
        await session.rollback()
        # Rollback expired the instance; restore its state explicitly before
        # mutating/logging (expired attr access = sync load = greenlet error).
        await session.refresh(instance)
        auth_failure = isinstance(exc, AzureAuthError) or (
            isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403)
        )
        if auth_failure:
            # Needs operator attention (bad secret, missing permission/consent).
            instance.status = ConnectorStatus.ERROR
        instance.error_message = f"{type(exc).__name__}: {exc}"[:500]
        await session.commit()
        log.warning(
            "azure_poller: %s (%s) poll failed%s: %s",
            instance.name,
            instance.connector_type,
            " — marked ERROR" if auth_failure else "",
            exc,
        )
    except Exception:
        log.error("azure_poller: failed to record poll failure", exc_info=True)


async def run_azure_poller(interval: float = 60.0) -> None:
    """Run the Azure poll loop forever, one cycle every `interval` seconds."""
    log.info("azure_poller: starting (interval=%.1fs)", interval)
    while True:
        try:
            await poll_all_azure_once()
        except asyncio.CancelledError:
            log.info("azure_poller: stopped")
            break
        except Exception as exc:
            log.error("azure_poller: unexpected error: %s", exc)
        await asyncio.sleep(interval)
