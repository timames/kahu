"""Ticket lifecycle — the destination for escalated and confirmed alerts.

An alert leaves the triage queue the moment any AlertDisposition row exists,
so a verdict that implies follow-up work must create a *destination* or the
alert silently vanishes from the UI. That destination is a Ticket:

- ``undetermined`` (escalate)  → INVESTIGATION ticket
- ``true_positive`` (confirm)  → INCIDENT ticket

``Ticket.alert_id`` is UNIQUE, and three call sites create tickets (web
disposition, mobile swipe, auto-confirm), so all creation funnels through the
idempotent :func:`ensure_ticket_for_verdict` — a second call returns the
existing ticket instead of violating the constraint.

Evidence convention: every function records hash-chained evidence but the
CALLER owns the commit (same contract as ``record_evidence`` itself).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.tickets import Ticket, TicketStatus, TicketType
from kahu.services.compliance.evidence import record_evidence
from kahu.services.triage.disposition import ALERT_DISPOSITIONED_CONTROLS
from kahu.services.triage.llm_triage import canonical_verdict

logger = logging.getLogger(__name__)

# Which disposition verdicts open which kind of ticket. Anything else
# (acknowledged / false_positive / benign_true_positive) needs no follow-up.
_VERDICT_TICKET_TYPE: dict[DispositionVerdict, TicketType] = {
    DispositionVerdict.UNDETERMINED: TicketType.INVESTIGATION,
    DispositionVerdict.TRUE_POSITIVE: TicketType.INCIDENT,
}


def _alert_severity(alert: Alert) -> str:
    return alert.severity.value if isinstance(alert.severity, Severity) else alert.severity


async def ensure_ticket_for_verdict(
    session: AsyncSession,
    alert: Alert,
    verdict: DispositionVerdict,
    analyst: str,
) -> Ticket | None:
    """Create the follow-up ticket a verdict implies, idempotently.

    Returns the existing ticket if one is already open for this alert
    (``Ticket.alert_id`` is UNIQUE), the newly created one otherwise, or
    None when the verdict implies no follow-up work. Caller owns the commit.
    """
    ticket_type = _VERDICT_TICKET_TYPE.get(verdict)
    if ticket_type is None:
        return None

    existing = await session.scalar(select(Ticket).where(Ticket.alert_id == alert.id))
    if existing is not None:
        return existing

    ticket = Ticket(
        alert_id=alert.id,
        title=alert.rule_description or f"Rule {alert.rule_id}",
        severity=_alert_severity(alert),
        ticket_type=ticket_type.value,
        status=TicketStatus.OPEN,
        assigned_to=analyst,
    )
    session.add(ticket)
    await session.flush()

    event_type = "alert_escalated" if ticket_type is TicketType.INVESTIGATION else "incident_opened"
    await record_evidence(
        session,
        event_type=event_type,
        control_tags=ALERT_DISPOSITIONED_CONTROLS,
        payload={
            "ticket_id": str(ticket.id),
            "alert_id": str(alert.id),
            "ticket_type": ticket_type.value,
            "severity": ticket.severity,
            "analyst": analyst,
        },
        actor=analyst,
    )
    logger.info(
        "Ticket %s (%s) opened for alert %s by %s",
        ticket.id,
        ticket_type.value,
        alert.id,
        analyst,
    )
    return ticket


async def _upsert_disposition(
    session: AsyncSession,
    alert_id: uuid.UUID,
    verdict: DispositionVerdict,
    analyst: str,
    notes: str | None,
) -> AlertDisposition:
    """Update the alert's existing disposition row or insert one.

    ``AlertDisposition.alert_id`` is UNIQUE and the alert almost always
    already has a row (the escalation/confirmation that opened the ticket),
    so this must update in place rather than insert a second row.
    """
    disposition = await session.scalar(
        select(AlertDisposition).where(AlertDisposition.alert_id == alert_id)
    )
    if disposition is None:
        disposition = AlertDisposition(alert_id=alert_id, verdict=verdict, analyst=analyst)
        session.add(disposition)
    else:
        disposition.verdict = verdict
        disposition.analyst = analyst
    if notes:
        disposition.notes = notes
    await session.flush()
    return disposition


async def promote_ticket(
    session: AsyncSession,
    ticket: Ticket,
    analyst: str,
) -> Ticket:
    """Promote an INVESTIGATION to an INCIDENT — the human confirmed it's real.

    Flips the ticket type, stamps promoted_at/promoted_by, and updates the
    alert's disposition to TRUE_POSITIVE (human ground truth). Caller owns
    the commit.
    """
    ticket.ticket_type = TicketType.INCIDENT.value
    ticket.promoted_at = datetime.now(UTC)
    ticket.promoted_by = analyst

    await _upsert_disposition(
        session,
        ticket.alert_id,
        DispositionVerdict.TRUE_POSITIVE,
        analyst,
        notes=None,
    )

    await record_evidence(
        session,
        event_type="investigation_promoted",
        control_tags=ALERT_DISPOSITIONED_CONTROLS,
        payload={
            "ticket_id": str(ticket.id),
            "alert_id": str(ticket.alert_id),
            "analyst": analyst,
        },
        actor=analyst,
    )
    logger.info("Ticket %s promoted to incident by %s", ticket.id, analyst)
    return ticket


async def close_ticket_with_verdict(
    session: AsyncSession,
    ticket: Ticket,
    verdict: str,
    notes: str,
    analyst: str,
) -> Ticket:
    """Close a ticket with a final human verdict and resolution notes.

    The verdict is upserted onto the alert's disposition row — a human close
    overwrites any earlier (including AI) verdict with ground truth. Caller
    owns the commit.
    """
    # canonical_verdict folds legacy spellings ("acknowledge"/"false_positive")
    # to the canonical DispositionVerdict value. "escalate" is a valid *model*
    # verdict but not a closing one — a case cannot be closed as "escalate".
    canonical = canonical_verdict(verdict)
    if canonical not in ("true_positive", "acknowledged"):
        raise ValueError(f"Invalid closing verdict: {verdict!r}")

    ticket.status = TicketStatus.CLOSED
    ticket.closed_by = analyst
    ticket.resolution_notes = notes

    await _upsert_disposition(
        session,
        ticket.alert_id,
        DispositionVerdict(canonical),
        analyst,
        notes=notes,
    )

    await record_evidence(
        session,
        event_type="ticket_closed",
        control_tags=ALERT_DISPOSITIONED_CONTROLS,
        payload={
            "ticket_id": str(ticket.id),
            "alert_id": str(ticket.alert_id),
            "ticket_type": ticket.ticket_type,
            "verdict": canonical,
            "analyst": analyst,
        },
        actor=analyst,
    )
    logger.info("Ticket %s closed as %s by %s", ticket.id, canonical, analyst)
    return ticket
