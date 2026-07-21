"""Stage 4 — Alert persistence, evidence recording, and notification dispatch.

Every detection, alert disposition, and response action is logged with full
pipeline provenance. This provenance chain is itself compliance evidence
(incident response and audit controls).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.evidence import EvidenceRecord

if TYPE_CHECKING:
    from kahu.services.triage.pipeline import PipelineResult

logger = logging.getLogger(__name__)

# Control tags for triage evidence — maps to NIST 800-171 / CMMC / HIPAA
ALERT_RAISED_CONTROLS = [
    "800-171:3.3.1",   # Create and retain audit records
    "800-171:3.3.2",   # Ensure actions are traceable
    "800-171:3.14.6",  # Monitor the system
    "800-171:3.14.7",  # Identify unauthorized use
    "HIPAA:164.312(b)",  # Audit controls
    "CIS:8.2",         # Collect audit logs
    "CIS:8.5",         # Collect detailed audit logs
]

ALERT_DISPOSITIONED_CONTROLS = [
    "800-171:3.6.1",   # Incident handling
    "800-171:3.6.2",   # Track/document/report incidents
    "HIPAA:164.308(a)(6)(ii)",  # Response and reporting
    "CIS:17.4",        # Establish incident handling process
]


async def persist_alert(
    result: PipelineResult,
    raw_alert: dict,
    session: AsyncSession,
) -> Alert:
    """Save a triaged alert to the database and record evidence."""
    rule = raw_alert.get("rule", {})

    alert = Alert(
        id=uuid.uuid4(),
        wazuh_alert_id=raw_alert.get("id", str(uuid.uuid4())),
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description", ""),
        severity=Severity(result.final_severity or "medium"),
        agent_name=raw_alert.get("agent", {}).get("name"),
        raw_event=raw_alert,
        enrichment=result.enrichment,
        llm_triage=result.llm_output,
        pipeline_provenance=result.provenance,
        control_tags=ALERT_RAISED_CONTROLS,
    )

    session.add(alert)
    await session.flush()

    # Record to evidence store
    await _record_evidence(
        session=session,
        event_type="alert_raised",
        control_tags=ALERT_RAISED_CONTROLS,
        payload={
            "alert_id": str(alert.id),
            "rule_id": alert.rule_id,
            "rule_description": alert.rule_description,
            "severity": alert.severity.value,
            "agent_name": alert.agent_name,
            "llm_degraded": result.llm_output.get("degraded", False) if result.llm_output else False,
        },
        actor="system:triage_pipeline",
    )

    await session.commit()
    logger.info(
        "Alert persisted: %s [%s] severity=%s agent=%s",
        alert.id, alert.rule_id, alert.severity.value, alert.agent_name,
    )
    return alert


async def record_disposition(
    alert_id: uuid.UUID,
    verdict: DispositionVerdict,
    analyst: str,
    notes: str | None,
    session: AsyncSession,
) -> AlertDisposition:
    """Record a human analyst's disposition of an alert."""
    disposition = AlertDisposition(
        id=uuid.uuid4(),
        alert_id=alert_id,
        verdict=verdict,
        analyst=analyst,
        notes=notes,
    )

    session.add(disposition)
    await session.flush()

    await _record_evidence(
        session=session,
        event_type="alert_dispositioned",
        control_tags=ALERT_DISPOSITIONED_CONTROLS,
        payload={
            "alert_id": str(alert_id),
            "verdict": verdict.value,
            "analyst": analyst,
            "notes": notes,
        },
        actor=analyst,
    )

    await session.commit()
    logger.info(
        "Alert %s dispositioned as %s by %s", alert_id, verdict.value, analyst,
    )
    return disposition


async def _record_evidence(
    session: AsyncSession,
    event_type: str,
    control_tags: list[str],
    payload: dict,
    actor: str,
) -> EvidenceRecord:
    """Append a hash-chained record to the evidence store."""
    # Get the previous hash for chain integrity
    previous_hash = await _get_latest_hash(session)

    # Compute this record's hash
    record_content = json.dumps(
        {"previous_hash": previous_hash, "event_type": event_type,
         "control_tags": control_tags, "payload": payload, "actor": actor},
        sort_keys=True, default=str,
    )
    record_hash = hashlib.sha256(record_content.encode()).hexdigest()

    record = EvidenceRecord(
        id=uuid.uuid4(),
        event_type=event_type,
        control_tags=control_tags,
        payload=payload,
        actor=actor,
        previous_hash=previous_hash,
        record_hash=record_hash,
    )
    session.add(record)
    return record


async def _get_latest_hash(session: AsyncSession) -> str:
    """Get the hash of the most recent evidence record for chain linking."""
    from sqlalchemy import select as sa_select, desc

    stmt = (
        sa_select(EvidenceRecord.record_hash)
        .order_by(desc(EvidenceRecord.timestamp))
        .limit(1)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    return row or "0" * 64  # Genesis hash for first record
