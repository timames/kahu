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
    HistoryAlertSummary,
    HistoryResponse,
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


@router.get("/history", response_model=HistoryResponse)
async def alert_history(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    verdict: str | None = Query(None),
    search: str | None = Query(None, max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> HistoryResponse:
    """Browse all historic alerts (dispositioned and pending)."""
    stmt = select(Alert).outerjoin(AlertDisposition).options(selectinload(Alert.disposition))

    if severity:
        stmt = stmt.where(Alert.severity == Severity(severity))
    if verdict:
        stmt = stmt.where(AlertDisposition.verdict == DispositionVerdict(verdict))
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            Alert.rule_description.ilike(pattern)
            | Alert.rule_id.ilike(pattern)
            | Alert.agent_name.ilike(pattern)
        )

    stmt = stmt.order_by(Alert.created_at.desc())

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = await session.scalar(count_stmt) or 0

    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    alerts = result.scalars().all()

    items = []
    for a in alerts:
        llm = a.llm_triage or {}
        items.append(HistoryAlertSummary(
            id=a.id,
            wazuh_alert_id=a.wazuh_alert_id,
            rule_id=a.rule_id,
            rule_description=a.rule_description,
            severity=a.severity.value if isinstance(a.severity, Severity) else a.severity,
            agent_name=a.agent_name,
            created_at=a.created_at,
            verdict=a.disposition.verdict.value if a.disposition else None,
            analyst=a.disposition.analyst if a.disposition else None,
            disposition_at=a.disposition.created_at if a.disposition else None,
            llm_explanation=llm.get("explanation"),
        ))

    return HistoryResponse(alerts=items, total=total, offset=offset, limit=limit)


@router.get("/runbooks")
async def list_runbooks():
    """Return simple runbooks for common alert types."""
    return {"runbooks": RUNBOOKS}


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

    from kahu.services.triage.poller import poller_running

    return PipelineStatusResponse(
        pipeline_running=poller_running(),
        ollama_healthy=ollama_ok,
        wazuh_api_healthy=wazuh_api_ok,
        wazuh_indexer_healthy=indexer_ok,
        pipeline_degraded=not ollama_ok,
    )


@router.post("/restart/{service}")
async def restart_service(service: str):
    """Restart a service component."""
    if service == "wazuh":
        # Re-authenticate to Wazuh to reset connection
        client = WazuhAPIClient()
        try:
            await client.authenticate()
            return {"status": "ok", "message": "Wazuh connection re-established"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    elif service == "pipeline":
        # Restart the poller task
        from kahu.services.triage.poller import restart_poller
        try:
            await restart_poller()
            return {"status": "ok", "message": "Pipeline restarted"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    elif service == "reeval":
        from kahu.services.triage.reeval import run_reeval_cycle
        try:
            stats = await run_reeval_cycle()
            return {"status": "ok", "message": f"Re-evaluated {stats['reviewed']} alerts, promoted {stats['promoted']}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    else:
        return {"status": "error", "message": f"Unknown service: {service}"}


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


# ── Runbooks ──────────────────────────────────────────────

RUNBOOKS = [
    {
        "id": "brute-force",
        "title": "Brute Force / Authentication Failure",
        "rule_ids": ["5503", "5551", "5710", "5712", "5720", "5763"],
        "severity": "high",
        "steps": [
            "Identify the source IP and target account from the alert details",
            "Check if the source IP is internal or external (whois / GeoIP lookup)",
            "Verify with the account owner whether this was legitimate activity",
            "If malicious: block the source IP at the firewall or WAF",
            "If the account was compromised: force password reset and revoke active sessions",
            "Search for lateral movement from the compromised account",
            "Document the incident and preserve logs as evidence",
        ],
    },
    {
        "id": "malware-detected",
        "title": "Malware or Suspicious File Detected",
        "rule_ids": ["554", "553", "100002"],
        "severity": "critical",
        "steps": [
            "Isolate the affected host from the network immediately",
            "Identify the file hash (MD5/SHA256) from the alert",
            "Check the hash against VirusTotal or your threat intel feed",
            "Determine how the file arrived (email attachment, download, USB, lateral movement)",
            "Run a full antivirus scan on the isolated host",
            "Check other hosts for the same file hash or indicators",
            "If confirmed malware: reimage the host from a known-good baseline",
            "Preserve forensic evidence before reimaging",
        ],
    },
    {
        "id": "privilege-escalation",
        "title": "Privilege Escalation Attempt",
        "rule_ids": ["5401", "5402", "5501", "5502", "18100", "18101"],
        "severity": "critical",
        "steps": [
            "Identify the user and process involved in the escalation",
            "Determine if this is an expected administrative action",
            "Check if the user account has legitimate admin privileges",
            "Review recent commands run by this user (audit logs)",
            "If unauthorized: disable the user account immediately",
            "Check for persistence mechanisms (cron jobs, scheduled tasks, services)",
            "Scan for rootkits or backdoors on the affected system",
            "Escalate to incident response team if confirmed",
        ],
    },
    {
        "id": "file-integrity",
        "title": "File Integrity Change (FIM)",
        "rule_ids": ["550", "553", "554"],
        "severity": "medium",
        "steps": [
            "Identify which file was modified and on which host",
            "Check if this was part of a scheduled change (patch, deployment)",
            "Compare the file hash against known-good baselines",
            "Review who made the change (process owner, user account)",
            "If unexpected: restore the file from backup",
            "Investigate how the modification occurred",
            "Update your FIM baseline if this was a legitimate change",
        ],
    },
    {
        "id": "network-anomaly",
        "title": "Suspicious Network Activity",
        "rule_ids": ["1002", "1003", "86601", "86602"],
        "severity": "high",
        "steps": [
            "Identify the source and destination IPs, ports, and protocols",
            "Check if the destination is a known-bad IP or domain (threat intel)",
            "Review DNS logs for related domain lookups",
            "Determine if this is C2 communication, data exfiltration, or scanning",
            "Block the suspicious destination at the firewall",
            "Investigate the source host for compromise indicators",
            "Capture network traffic for forensic analysis if ongoing",
        ],
    },
    {
        "id": "policy-violation",
        "title": "Security Policy Violation",
        "rule_ids": ["510", "512", "515", "516"],
        "severity": "low",
        "steps": [
            "Identify the policy that was violated",
            "Determine if this is a misconfiguration or intentional bypass",
            "Contact the responsible team or user for context",
            "If misconfiguration: remediate and verify the fix",
            "If intentional bypass: escalate to management",
            "Update security policies or exceptions as needed",
            "Log the violation for compliance reporting",
        ],
    },
]
