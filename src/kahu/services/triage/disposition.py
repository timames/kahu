"""Stage 4 — Alert persistence, evidence recording, and notification dispatch.

Every detection, alert disposition, and response action is logged with full
pipeline provenance. This provenance chain is itself compliance evidence
(incident response and audit controls).
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.services.compliance.controls import tags_for_alert
from kahu.services.compliance.evidence import record_evidence

if TYPE_CHECKING:
    from kahu.services.triage.pipeline import PipelineResult

logger = logging.getLogger(__name__)

# Analyst identity stamped on every automatic disposition (auto_disposition.py).
# Defined here — not in auto_disposition — so that enrichment can import it
# without a cycle (enrichment ← llm_triage ← auto_disposition). Anything that
# computes disposition *statistics* fed back into triage (rule/agent history in
# enrichment, rule FP rate in auto_disposition) MUST exclude this analyst:
# AI dispositions are model output, and letting them re-enter the model's
# evidence base creates a self-reinforcing loop (observed live: a rule's
# recent-100 window became 100% kahu-ai auto-confirms, so every new triage was
# told "100% true-positive history" and auto-confirmed again). Human
# dispositions are the only ground truth.
AI_ANALYST = "kahu-ai"

# Control tags for triage evidence — maps to NIST 800-171 / CMMC / HIPAA
ALERT_RAISED_CONTROLS = [
    "800-171:3.3.1",  # Create and retain audit records
    "800-171:3.3.2",  # Ensure actions are traceable
    "800-171:3.14.6",  # Monitor the system
    "800-171:3.14.7",  # Identify unauthorized use
    "HIPAA:164.312(b)",  # Audit controls
    "CIS:8.2",  # Collect audit logs
    "CIS:8.5",  # Collect detailed audit logs
    "SOC2:CC2.1",  # Generated info for system controls
    "SOC2:CC7.1",  # Detection and monitoring
    "SOC2:CC7.2",  # Monitor for anomalies
]

ALERT_DISPOSITIONED_CONTROLS = [
    "800-171:3.6.1",  # Incident handling
    "800-171:3.6.2",  # Track/document/report incidents
    "HIPAA:164.308(a)(6)(ii)",  # Response and reporting
    "CIS:17.4",  # Establish incident handling process
    "SOC2:CC7.3",  # Evaluate security events
    "SOC2:CC7.4",  # Respond to identified incidents
]


async def persist_alert(
    result: PipelineResult,
    raw_alert: dict,
    session: AsyncSession,
) -> Alert:
    """Save a triaged alert to the database and record evidence."""
    rule = raw_alert.get("rule", {})

    # Derive compliance control tags from Wazuh rule groups
    alert_control_tags = tags_for_alert(raw_alert) or ALERT_RAISED_CONTROLS

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
        control_tags=alert_control_tags,
        muted=result.muted,
    )

    session.add(alert)
    await session.flush()

    # Record to evidence store
    await record_evidence(
        session,
        event_type="alert_raised",
        control_tags=alert_control_tags,
        payload={
            "alert_id": str(alert.id),
            "rule_id": alert.rule_id,
            "rule_description": alert.rule_description,
            "severity": alert.severity.value,
            "agent_name": alert.agent_name,
            "llm_degraded": result.llm_output.get("degraded", False)
            if result.llm_output
            else False,
        },
        actor="system:triage_pipeline",
    )

    await session.commit()
    logger.info(
        "Alert persisted: %s [%s] severity=%s agent=%s",
        alert.id,
        alert.rule_id,
        alert.severity.value,
        alert.agent_name,
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

    await record_evidence(
        session,
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
        "Alert %s dispositioned as %s by %s",
        alert_id,
        verdict.value,
        analyst,
    )
    return disposition
