"""Triage pipeline API — alert queue, detail, disposition, and batch ingestion."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kahu.clients.ollama import OllamaClient
from kahu.clients.wazuh import WazuhAPIClient, WazuhIndexerClient
from kahu.db import get_session
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.schemas.triage import (
    AlertDetail,
    AlertSummary,
    DispositionIn,
    DispositionOut,
    PipelineBatchRequest,
    PipelineBatchResponse,
    PipelineStatusResponse,
    TriageQueueResponse,
)
from kahu.services.triage.disposition import record_disposition
from kahu.services.triage.pipeline import run_pipeline_batch

router = APIRouter()


@router.get("/queue", response_model=TriageQueueResponse)
async def get_triage_queue(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    undispositioned_only: bool = Query(True),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> TriageQueueResponse:
    """Get the alert triage queue, ordered by severity and recency."""
    stmt = select(Alert).options(selectinload(Alert.disposition))

    if severity:
        stmt = stmt.where(Alert.severity == Severity(severity))

    if undispositioned_only:
        stmt = stmt.outerjoin(AlertDisposition).where(AlertDisposition.id.is_(None))

    # Order: critical first, then by creation time descending
    severity_order = case(
        {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        },
        value=Alert.severity,
        else_=5,
    )
    stmt = stmt.order_by(severity_order, Alert.created_at.desc())

    # Count total before pagination
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = await session.scalar(count_stmt) or 0

    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    alerts = result.scalars().all()

    return TriageQueueResponse(
        alerts=[_to_summary(a) for a in alerts],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert_detail(
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> AlertDetail:
    """Get full detail for a single alert including enrichment and LLM triage."""
    stmt = (
        select(Alert)
        .options(selectinload(Alert.disposition))
        .where(Alert.id == alert_id)
    )
    result = await session.execute(stmt)
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _to_detail(alert)


@router.post("/alerts/{alert_id}/disposition", response_model=DispositionOut)
async def disposition_alert(
    alert_id: uuid.UUID,
    body: DispositionIn,
    session: AsyncSession = Depends(get_session),
) -> DispositionOut:
    """Record a human analyst's disposition of an alert.

    Every disposition is logged to the evidence store with full attribution —
    this is incident-response evidence (800-171 3.6.x).
    """
    # Verify alert exists
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Check for existing disposition
    existing = await session.execute(
        select(AlertDisposition).where(AlertDisposition.alert_id == alert_id)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Alert already dispositioned")

    disposition = await record_disposition(
        alert_id=alert_id,
        verdict=DispositionVerdict(body.verdict),
        analyst=body.analyst,
        notes=body.notes,
        session=session,
    )

    return DispositionOut(
        id=disposition.id,
        alert_id=disposition.alert_id,
        verdict=disposition.verdict.value,
        analyst=disposition.analyst,
        notes=disposition.notes,
        created_at=disposition.created_at,
    )


@router.post("/ingest", response_model=PipelineBatchResponse)
async def ingest_alerts(
    body: PipelineBatchRequest,
    session: AsyncSession = Depends(get_session),
) -> PipelineBatchResponse:
    """Ingest a batch of raw Wazuh alerts through the triage pipeline."""
    indexer = WazuhIndexerClient()
    ollama = OllamaClient()

    _, stats = await run_pipeline_batch(
        raw_alerts=body.alerts,
        session=session,
        indexer=indexer,
        ollama=ollama,
    )

    return PipelineBatchResponse(
        processed=stats.total,
        filtered=stats.filtered,
        triaged=stats.triaged,
        persisted=stats.persisted,
        errors=stats.errors,
    )


@router.get("/status", response_model=PipelineStatusResponse)
async def pipeline_status() -> PipelineStatusResponse:
    """Check health of all pipeline dependencies."""
    ollama = OllamaClient()
    wazuh_api = WazuhAPIClient()
    indexer = WazuhIndexerClient()

    ollama_ok = await ollama.health()

    try:
        await wazuh_api.authenticate()
        wazuh_api_ok = True
    except Exception:
        wazuh_api_ok = False

    try:
        await indexer.search(index="wazuh-alerts-*", query={"size": 0})
        indexer_ok = True
    except Exception:
        indexer_ok = False

    return PipelineStatusResponse(
        ollama_healthy=ollama_ok,
        wazuh_api_healthy=wazuh_api_ok,
        wazuh_indexer_healthy=indexer_ok,
        pipeline_degraded=not ollama_ok,
    )


def _to_summary(alert: Alert) -> AlertSummary:
    llm = alert.llm_triage or {}
    return AlertSummary(
        id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        severity=alert.severity.value if isinstance(alert.severity, Severity) else alert.severity,
        agent_name=alert.agent_name,
        created_at=alert.created_at,
        has_disposition=alert.disposition is not None,
        llm_explanation=llm.get("explanation"),
        degraded=llm.get("degraded", False),
    )


def _to_detail(alert: Alert) -> AlertDetail:
    disposition = None
    if alert.disposition is not None:
        disposition = DispositionOut(
            id=alert.disposition.id,
            alert_id=alert.disposition.alert_id,
            verdict=alert.disposition.verdict.value,
            analyst=alert.disposition.analyst,
            notes=alert.disposition.notes,
            created_at=alert.disposition.created_at,
        )

    return AlertDetail(
        id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        severity=alert.severity.value if isinstance(alert.severity, Severity) else alert.severity,
        agent_name=alert.agent_name,
        created_at=alert.created_at,
        raw_event=alert.raw_event,
        enrichment=alert.enrichment,
        llm_triage=alert.llm_triage,
        pipeline_provenance=alert.pipeline_provenance,
        control_tags=alert.control_tags,
        disposition=disposition,
    )
