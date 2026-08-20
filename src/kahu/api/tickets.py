"""Case management API — investigations and incidents (web UI).

Cases ARE tickets: an escalated alert opens an INVESTIGATION, a confirmed
alert opens an INCIDENT, and an investigation can be promoted to an incident.
Closing a case requires a final human verdict + resolution notes, which are
upserted onto the alert's disposition row and recorded as evidence.

Mounted auth-protected at /api/tickets. The mobile API (/m/tickets) shares
the same Ticket model but keeps its own simpler XP-flavoured surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kahu.api.deps import get_current_user
from kahu.db import get_session
from kahu.models.tickets import Ticket, TicketStatus, TicketType
from kahu.models.users import User
from kahu.services.tickets import close_ticket_with_verdict, promote_ticket

router = APIRouter()


class CaseTicketOut(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    title: str
    severity: str
    ticket_type: str
    status: str
    assigned_to: str
    closed_by: str | None
    resolution_notes: str | None
    promoted_at: datetime | None
    promoted_by: str | None
    created_at: datetime
    updated_at: datetime
    # Alert summary for the case card
    alert_rule_id: str | None = None
    alert_rule_description: str | None = None
    alert_agent_name: str | None = None
    alert_created_at: datetime | None = None
    alert_llm_explanation: str | None = None
    alert_degraded: bool = False


class CaseTicketDetailOut(CaseTicketOut):
    alert_recommended_actions: list[str] = []
    alert_enrichment: dict | None = None


class CaseListResponse(BaseModel):
    tickets: list[CaseTicketOut]
    total: int
    offset: int
    limit: int


class CaseCountsResponse(BaseModel):
    investigations_open: int
    incidents_open: int


class CaseCloseIn(BaseModel):
    verdict: str = Field(..., pattern="^(true_positive|false_positive|acknowledged)$")
    resolution_notes: str = Field(..., min_length=1, max_length=4000)


class CaseUpdateIn(BaseModel):
    title: str | None = None
    status: str | None = Field(None, pattern="^(open|in_progress)$")
    assigned_to: str | None = None


def _case_out(t: Ticket, detail: bool = False) -> CaseTicketOut:
    alert = t.alert
    llm = (alert.llm_triage or {}) if alert else {}
    base = {
        "id": t.id,
        "alert_id": t.alert_id,
        "title": t.title,
        "severity": t.severity,
        "ticket_type": t.ticket_type or TicketType.INCIDENT.value,
        "status": t.status.value,
        "assigned_to": t.assigned_to,
        "closed_by": t.closed_by,
        "resolution_notes": t.resolution_notes,
        "promoted_at": t.promoted_at,
        "promoted_by": t.promoted_by,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "alert_rule_id": alert.rule_id if alert else None,
        "alert_rule_description": alert.rule_description if alert else None,
        "alert_agent_name": alert.agent_name if alert else None,
        "alert_created_at": alert.created_at if alert else None,
        "alert_llm_explanation": llm.get("explanation"),
        "alert_degraded": llm.get("degraded", False),
    }
    if detail:
        return CaseTicketDetailOut(
            **base,
            alert_recommended_actions=llm.get("recommended_actions", []),
            alert_enrichment=alert.enrichment if alert else None,
        )
    return CaseTicketOut(**base)


async def _load_ticket(session: AsyncSession, ticket_id: uuid.UUID) -> Ticket:
    stmt = select(Ticket).options(selectinload(Ticket.alert)).where(Ticket.id == ticket_id)
    ticket = (await session.execute(stmt)).scalar_one_or_none()
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@router.get("/counts", response_model=CaseCountsResponse)
async def case_counts(
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> CaseCountsResponse:
    """Open-case counts for nav badges."""
    stmt = (
        select(Ticket.ticket_type, func.count())
        .where(Ticket.status != TicketStatus.CLOSED)
        .group_by(Ticket.ticket_type)
    )
    counts = dict((await session.execute(stmt)).all())
    return CaseCountsResponse(
        investigations_open=counts.get(TicketType.INVESTIGATION.value, 0),
        # Legacy rows may carry ticket_type NULL — those default to incident.
        incidents_open=counts.get(TicketType.INCIDENT.value, 0) + counts.get(None, 0),
    )


@router.get("", response_model=CaseListResponse)
async def list_cases(
    ticket_type: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> CaseListResponse:
    """List case tickets with their alert summaries."""
    stmt = select(Ticket).options(selectinload(Ticket.alert))

    if ticket_type in (TicketType.INVESTIGATION.value, TicketType.INCIDENT.value):
        if ticket_type == TicketType.INCIDENT.value:
            # Legacy rows with NULL ticket_type are incidents.
            stmt = stmt.where((Ticket.ticket_type == ticket_type) | (Ticket.ticket_type.is_(None)))
        else:
            stmt = stmt.where(Ticket.ticket_type == ticket_type)

    if status == "open":
        stmt = stmt.where(Ticket.status != TicketStatus.CLOSED)
    elif status in ("in_progress", "closed"):
        stmt = stmt.where(Ticket.status == TicketStatus(status))

    stmt = stmt.order_by(Ticket.created_at.desc())

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = await session.scalar(count_stmt) or 0

    offset = max(0, offset)
    limit = max(1, min(200, limit))
    result = await session.execute(stmt.offset(offset).limit(limit))
    tickets = result.scalars().all()

    return CaseListResponse(
        tickets=[_case_out(t) for t in tickets],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{ticket_id}", response_model=CaseTicketDetailOut)
async def get_case(
    ticket_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> CaseTicketDetailOut:
    """Full case detail including alert enrichment and recommended actions."""
    ticket = await _load_ticket(session, ticket_id)
    out = _case_out(ticket, detail=True)
    assert isinstance(out, CaseTicketDetailOut)  # noqa: S101 — narrowing
    return out


@router.post("/{ticket_id}/promote", response_model=CaseTicketOut)
async def promote_case(
    ticket_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
    user: User = Depends(get_current_user),  # noqa: B008
) -> CaseTicketOut:
    """Promote an investigation to an incident (human-confirmed true positive)."""
    ticket = await _load_ticket(session, ticket_id)
    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Ticket is closed")
    if (ticket.ticket_type or TicketType.INCIDENT.value) == TicketType.INCIDENT.value:
        raise HTTPException(status_code=409, detail="Ticket is already an incident")

    await promote_ticket(session, ticket, analyst=user.username)
    await session.commit()
    # updated_at is SQL-side onupdate → expired after the UPDATE; refresh it
    # explicitly so _case_out doesn't trigger a sync lazy-load in async context.
    await session.refresh(ticket, attribute_names=["updated_at"])
    return _case_out(ticket)


@router.post("/{ticket_id}/close", response_model=CaseTicketOut)
async def close_case(
    ticket_id: uuid.UUID,
    body: CaseCloseIn,
    session: AsyncSession = Depends(get_session),  # noqa: B008
    user: User = Depends(get_current_user),  # noqa: B008
) -> CaseTicketOut:
    """Close a case with a final verdict + resolution notes (evidence-recorded)."""
    ticket = await _load_ticket(session, ticket_id)
    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Ticket already closed")

    await close_ticket_with_verdict(
        session,
        ticket,
        verdict=body.verdict,
        notes=body.resolution_notes,
        analyst=user.username,
    )
    await session.commit()
    await session.refresh(ticket, attribute_names=["updated_at"])
    return _case_out(ticket)


@router.patch("/{ticket_id}", response_model=CaseTicketOut)
async def update_case(
    ticket_id: uuid.UUID,
    body: CaseUpdateIn,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> CaseTicketOut:
    """Update title / open↔in_progress status / assignee.

    Closing goes through POST /{id}/close — it requires a verdict.
    """
    ticket = await _load_ticket(session, ticket_id)
    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Ticket is closed")

    if body.title is not None:
        ticket.title = body.title
    if body.status is not None:
        ticket.status = TicketStatus(body.status)
    if body.assigned_to is not None:
        ticket.assigned_to = body.assigned_to
    await session.commit()
    await session.refresh(ticket, attribute_names=["updated_at"])
    return _case_out(ticket)
