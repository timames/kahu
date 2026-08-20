"""Triage pipeline API — alert queue, detail, disposition, and batch ingestion."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kahu.api.deps import get_current_user
from kahu.clients.ollama import OllamaClient
from kahu.clients.wazuh import WazuhAPIClient, WazuhIndexerClient
from kahu.db import get_session
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, MutedRule, Severity
from kahu.models.users import User
from kahu.schemas.triage import (
    AlertDetail,
    AlertSummary,
    DispositionIn,
    DispositionOut,
    HistoryAlertSummary,
    HistoryResponse,
    LogStorageResponse,
    MuteCreate,
    MutedRuleOut,
    MutesResponse,
    PipelineStatusResponse,
    TriageQueueResponse,
    WazuhLog,
    WazuhLogsResponse,
)
from kahu.services.compliance.evidence import record_evidence
from kahu.services.tickets import ensure_ticket_for_verdict
from kahu.services.triage.auto_disposition import TOLERANCE_CHANGE_CONTROLS
from kahu.services.triage.disposition import record_disposition
from kahu.services.triage.filters import CRITICAL_RULE_IDS

router = APIRouter()


@router.get("/queue", response_model=TriageQueueResponse)
async def get_triage_queue(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),  # noqa: B008
    undispositioned_only: bool = Query(True),  # noqa: B008
    offset: int = Query(0, ge=0),  # noqa: B008
    limit: int = Query(50, ge=1, le=200),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> TriageQueueResponse:
    """Get the alert triage queue, ordered by severity and recency."""
    # Muted alerts are persisted for audit but never surface in the queue.
    stmt = select(Alert).options(selectinload(Alert.disposition)).where(Alert.muted == False)  # noqa: E712

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
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),  # noqa: B008
    verdict: str | None = Query(None),  # noqa: B008
    search: str | None = Query(None, max_length=200),  # noqa: B008
    offset: int = Query(0, ge=0),  # noqa: B008
    limit: int = Query(50, ge=1, le=200),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
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
        items.append(
            HistoryAlertSummary(
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
                muted=a.muted,
            )
        )

    return HistoryResponse(alerts=items, total=total, offset=offset, limit=limit)


# ── Rule mutes ────────────────────────────────────────────


def _active_mute_clause():
    now = datetime.now(UTC)
    return (
        MutedRule.active == True,  # noqa: E712 — SQL expression
        or_(MutedRule.expires_at.is_(None), MutedRule.expires_at > now),
    )


@router.get("/mutes", response_model=MutesResponse)
async def list_mutes(
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> MutesResponse:
    """List active (unexpired) rule mutes with a sample rule description."""
    stmt = select(MutedRule).where(*_active_mute_clause()).order_by(MutedRule.created_at.desc())
    mutes = (await session.execute(stmt)).scalars().all()

    # Most recent alert description per muted rule so the UI can label them.
    descriptions: dict[str, str] = {}
    for rule_id in {m.rule_id for m in mutes}:
        desc = await session.scalar(
            select(Alert.rule_description)
            .where(Alert.rule_id == rule_id)
            .order_by(Alert.created_at.desc())
            .limit(1)
        )
        if desc:
            descriptions[rule_id] = desc

    return MutesResponse(
        mutes=[
            MutedRuleOut(
                id=m.id,
                rule_id=m.rule_id,
                reason=m.reason,
                created_by=m.created_by,
                expires_at=m.expires_at,
                created_at=m.created_at,
                rule_description=descriptions.get(m.rule_id),
            )
            for m in mutes
        ]
    )


@router.post("/mutes", response_model=MutedRuleOut, status_code=201)
async def create_mute(
    body: MuteCreate,
    session: AsyncSession = Depends(get_session),  # noqa: B008
    user: User = Depends(get_current_user),  # noqa: B008
) -> MutedRuleOut:
    """Mute a rule: its alerts are persisted but skip LLM triage and the queue.

    Guardrail — the governing invariant: rules in CRITICAL_RULE_IDS can never
    be muted, and (enforced in the pipeline) no mute applies to alerts whose
    deterministic severity is high/critical. Muting is a suppression-posture
    change, so it is recorded in the hash-chained evidence store with the
    actor who made it.
    """
    if body.rule_id in CRITICAL_RULE_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Rule {body.rule_id} is a critical rule and can never be muted",
        )

    # Idempotency: refuse a duplicate active mute for the same rule.
    existing = await session.scalar(
        select(MutedRule).where(MutedRule.rule_id == body.rule_id, *_active_mute_clause())
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Rule {body.rule_id} is already muted")

    expires_at = None
    if body.duration == "24h":
        expires_at = datetime.now(UTC) + timedelta(hours=24)
    elif body.duration == "7d":
        expires_at = datetime.now(UTC) + timedelta(days=7)

    mute = MutedRule(
        id=uuid.uuid4(),
        rule_id=body.rule_id,
        reason=body.reason,
        created_by=user.email,
        expires_at=expires_at,
        active=True,
    )
    session.add(mute)
    await session.flush()

    await record_evidence(
        session,
        event_type="rule_muted",
        control_tags=TOLERANCE_CHANGE_CONTROLS,
        payload={
            "mute_id": str(mute.id),
            "rule_id": mute.rule_id,
            "reason": mute.reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "duration": body.duration or "forever",
        },
        actor=user.email,
    )
    await session.commit()

    return MutedRuleOut(
        id=mute.id,
        rule_id=mute.rule_id,
        reason=mute.reason,
        created_by=mute.created_by,
        expires_at=mute.expires_at,
        created_at=mute.created_at,
    )


@router.delete("/mutes/{mute_id}")
async def delete_mute(
    mute_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
    user: User = Depends(get_current_user),  # noqa: B008
) -> dict:
    """Unmute: deactivate the mute (audit row is kept) and record evidence."""
    mute = await session.get(MutedRule, mute_id)
    if mute is None:
        raise HTTPException(status_code=404, detail="Mute not found")

    mute.active = False
    await record_evidence(
        session,
        event_type="rule_unmuted",
        control_tags=TOLERANCE_CHANGE_CONTROLS,
        payload={"mute_id": str(mute.id), "rule_id": mute.rule_id},
        actor=user.email,
    )
    await session.commit()
    return {"status": "ok", "rule_id": mute.rule_id}


# Wazuh rule.level → Kahu severity band. These bounds mirror the mapping the
# poller uses when it ingests alerts, so the "All logs" firehose and the triaged
# queue label the same event identically.
_SEVERITY_LEVEL_RANGES: dict[str, tuple[int, int]] = {
    "critical": (13, 100),
    "high": (10, 12),
    "medium": (7, 9),
    "low": (4, 6),
    "info": (0, 3),
}


def _level_to_severity(level: int) -> str:
    for band, (lo, hi) in _SEVERITY_LEVEL_RANGES.items():
        if lo <= level <= hi:
            return band
    return "info"


@router.get("/wazuh-logs", response_model=WazuhLogsResponse)
async def wazuh_logs(
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),  # noqa: B008
    search: str | None = Query(None, max_length=200),  # noqa: B008
    offset: int = Query(0, ge=0, le=9000),  # noqa: B008
    limit: int = Query(100, ge=1, le=200),  # noqa: B008
) -> WazuhLogsResponse:
    """Browse the full Wazuh alert firehose straight from the indexer.

    Unlike ``/queue`` and ``/history`` (which read Kahu's own DB of triaged
    alerts), this streams every event Wazuh has indexed in ``wazuh-alerts-*`` —
    the raw source of truth. Read-only: these are not Kahu alerts and carry no
    disposition.
    """
    filters: list[dict] = []
    if severity:
        lo, hi = _SEVERITY_LEVEL_RANGES[severity]
        filters.append({"range": {"rule.level": {"gte": lo, "lte": hi}}})

    query: dict = {"match_all": {}}
    if search:
        query = {
            "multi_match": {
                "query": search,
                "fields": ["rule.description", "agent.name", "data.srcip", "full_log"],
                "type": "best_fields",
                "lenient": True,
            }
        }

    body = {
        "from": offset,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [query], "filter": filters}},
    }

    indexer = WazuhIndexerClient()
    try:
        result = await indexer.search(index="wazuh-alerts-*", query=body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503, detail="Wazuh indexer unavailable"
        ) from exc

    hits = result.get("hits", {})
    total_raw = hits.get("total", 0)
    total = total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw

    logs: list[WazuhLog] = []
    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        data = src.get("data", {}) or {}
        level = int(rule.get("level", 0) or 0)
        logs.append(
            WazuhLog(
                id=str(hit.get("_id", "")),
                timestamp=src.get("timestamp") or src.get("@timestamp"),
                rule_id=str(rule.get("id", "")),
                rule_level=level,
                severity=_level_to_severity(level),
                rule_description=rule.get("description", "") or "",
                agent_name=agent.get("name"),
                src_ip=data.get("srcip"),
                location=src.get("location"),
                full_log=src.get("full_log"),
            )
        )

    return WazuhLogsResponse(logs=logs, total=total, offset=offset, limit=limit)


def _sum_disk_bytes(allocation: list) -> tuple[int, int, int]:
    """Sum total/used/available disk bytes across the indexer's data nodes.

    ``_cat/allocation`` returns one row per node plus (sometimes) an UNASSIGNED
    row with empty disk fields; those are skipped. Requested with bytes=b so
    every field is a plain integer string.
    """
    total = used = avail = 0
    for row in allocation:
        if not row.get("node") or row.get("node") == "UNASSIGNED":
            continue
        try:
            total += int(row.get("disk.total") or 0)
            used += int(row.get("disk.used") or 0)
            avail += int(row.get("disk.avail") or 0)
        except (TypeError, ValueError):
            continue
    return total, used, avail


@router.get("/log-storage", response_model=LogStorageResponse)
async def log_storage() -> LogStorageResponse:
    """Estimate how long Wazuh logs can be retained before disk fills.

    Reads live indexer telemetry — cluster disk allocation, the ``wazuh-alerts-*``
    store size and doc count, and the timestamp span of stored logs — then
    projects the current ingest rate against free disk to answer "how many days
    of logs can we hold before old ones must roll off."
    """
    indexer = WazuhIndexerClient()
    try:
        allocation = await indexer.get("_cat/allocation", {"format": "json", "bytes": "b"})
        stats = await indexer.get("wazuh-alerts-*/_stats/store,docs")
        span = await indexer.search(
            index="wazuh-alerts-*",
            query={
                "size": 0,
                "aggs": {
                    "min_ts": {"min": {"field": "timestamp"}},
                    "max_ts": {"max": {"field": "timestamp"}},
                },
            },
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Wazuh indexer unavailable") from exc

    disk_total, disk_used, disk_avail = _sum_disk_bytes(
        allocation if isinstance(allocation, list) else []
    )

    all_total = ((stats or {}).get("_all", {}) or {}).get("total", {}) or {}
    logs_size = int((all_total.get("store", {}) or {}).get("size_in_bytes", 0) or 0)
    logs_docs = int((all_total.get("docs", {}) or {}).get("count", 0) or 0)

    aggs = (span or {}).get("aggregations", {}) or {}
    min_ms = (aggs.get("min_ts", {}) or {}).get("value")
    max_ms = (aggs.get("max_ts", {}) or {}).get("value")
    oldest = datetime.fromtimestamp(min_ms / 1000, tz=UTC) if min_ms else None
    newest = datetime.fromtimestamp(max_ms / 1000, tz=UTC) if max_ms else None

    span_days = 0.0
    if oldest and newest:
        span_days = max((newest - oldest).total_seconds() / 86400.0, 0.0)

    # Below a meaningful window the per-day rate is noise, so leave the
    # projections at zero rather than reporting a wild extrapolation.
    bytes_per_day = logs_size / span_days if span_days > 0.01 and logs_size > 0 else 0.0
    docs_per_day = logs_docs / span_days if span_days > 0.01 and logs_docs > 0 else 0.0

    days_until_full = disk_avail / bytes_per_day if bytes_per_day > 0 else 0.0
    total_capacity_days = (disk_avail + logs_size) / bytes_per_day if bytes_per_day > 0 else 0.0

    return LogStorageResponse(
        disk_total_bytes=disk_total,
        disk_used_bytes=disk_used,
        disk_available_bytes=disk_avail,
        logs_size_bytes=logs_size,
        logs_doc_count=logs_docs,
        oldest_log=oldest,
        newest_log=newest,
        span_days=round(span_days, 2),
        bytes_per_day=round(bytes_per_day, 2),
        docs_per_day=round(docs_per_day, 2),
        retention_days_current=round(span_days, 2),
        days_until_full=round(days_until_full, 1),
        total_capacity_days=round(total_capacity_days, 1),
    )


@router.get("/runbooks")
async def list_runbooks():
    """Return simple runbooks for common alert types."""
    return {"runbooks": RUNBOOKS}


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert_detail(
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> AlertDetail:
    """Get full detail for a single alert including enrichment and LLM triage."""
    stmt = select(Alert).options(selectinload(Alert.disposition)).where(Alert.id == alert_id)
    result = await session.execute(stmt)
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _to_detail(alert)


@router.post("/alerts/{alert_id}/disposition", response_model=DispositionOut)
async def disposition_alert(
    alert_id: uuid.UUID,
    body: DispositionIn,
    session: AsyncSession = Depends(get_session),  # noqa: B008
    user: User = Depends(get_current_user),  # noqa: B008
) -> DispositionOut:
    """Record a human analyst's disposition of an alert.

    Every disposition is logged to the evidence store with full attribution —
    this is incident-response evidence (800-171 3.6.x). An escalation
    (undetermined) opens an investigation ticket and a confirmation
    (true_positive) opens an incident ticket, so the alert has a destination
    once it leaves the queue.
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

    # Attribute to the authenticated user, not the client-supplied string.
    analyst = user.username or body.analyst

    disposition = await record_disposition(
        alert_id=alert_id,
        verdict=DispositionVerdict(body.verdict),
        analyst=analyst,
        notes=body.notes,
        session=session,
    )

    ticket = await ensure_ticket_for_verdict(session, alert, disposition.verdict, analyst)
    await session.commit()

    return DispositionOut(
        id=disposition.id,
        alert_id=disposition.alert_id,
        verdict=disposition.verdict.value,
        analyst=disposition.analyst,
        notes=disposition.notes,
        created_at=disposition.created_at,
        ticket_id=ticket.id if ticket else None,
        ticket_type=ticket.ticket_type if ticket else None,
    )


@router.get("/status", response_model=PipelineStatusResponse)
async def pipeline_status() -> PipelineStatusResponse:
    """Check health of all pipeline dependencies."""
    ollama = OllamaClient()
    wazuh_api = WazuhAPIClient()
    indexer = WazuhIndexerClient()

    ollama_ok = await ollama.health()
    # Reachability alone isn't enough — the API answers with no model resident.
    # Degradation is driven by whether the model is actually loaded.
    model_loaded = await ollama.model_loaded() if ollama_ok else False

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
        ollama_model_loaded=model_loaded,
        wazuh_api_healthy=wazuh_api_ok,
        wazuh_indexer_healthy=indexer_ok,
        pipeline_degraded=not (ollama_ok and model_loaded),
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
            return {
                "status": "ok",
                "message": f"Re-evaluated {stats['reviewed']} alerts, promoted {stats['promoted']}",
            }
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
