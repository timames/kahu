"""Mobile PWA API — glance, feed, swipe, score, coach."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from kahu.db import get_session
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.tickets import Ticket, TicketStatus
from kahu.models.xp import XpEvent
from kahu.services.triage.disposition import record_disposition

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class GlanceResponse(BaseModel):
    color: str  # green | yellow | red
    count: int
    headline: str
    breakdown: dict[str, int]
    last_updated: datetime


class FeedCard(BaseModel):
    id: uuid.UUID
    severity: str
    title: str
    explanation: str
    ai_verdict: str | None  # true_positive, false_positive, escalate
    ai_confidence: float
    agent: str | None
    source_ip: str | None
    timestamp: datetime
    recommended_actions: list[str]
    controls: list[str]


class FeedResponse(BaseModel):
    cards: list[FeedCard]
    remaining: int


class SwipeIn(BaseModel):
    direction: str = Field(..., pattern="^(right|left|up)$")
    analyst: str = Field(default="mobile-user", min_length=1, max_length=255)
    notes: str | None = None


class SwipeOut(BaseModel):
    id: uuid.UUID
    verdict: str
    message: str
    xp_earned: int
    ticket_id: uuid.UUID | None = None


class ScoreResponse(BaseModel):
    score: int  # 0-100
    xp: int
    streak_days: int
    alerts_handled_today: int
    avg_response_minutes: float | None
    trend: str  # up | down | steady
    badges: list[dict[str, str]]
    weekly_summary: str
    open_tickets: int


class CoachResponse(BaseModel):
    lesson_title: str
    lesson_body: str
    duration_seconds: int
    controls_satisfied: list[str]
    next_tip: str


# ---------------------------------------------------------------------------
# Glance — one color, one number, one sentence
# ---------------------------------------------------------------------------

@router.get("/glance", response_model=GlanceResponse)
async def glance(session: AsyncSession = Depends(get_session)) -> GlanceResponse:
    """The lock-screen view. One color, one number, one sentence."""

    # Count undispositioned alerts by severity
    stmt = (
        select(Alert.severity, func.count())
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
        .group_by(Alert.severity)
    )
    result = await session.execute(stmt)
    counts = {row[0].value if isinstance(row[0], Severity) else row[0]: row[1] for row in result.all()}

    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)
    info = counts.get("info", 0)
    total = critical + high + medium + low + info

    # Determine color
    if critical > 0:
        color = "red"
        headline = f"{critical} critical alert{'s' if critical != 1 else ''} need your attention right now."
    elif high > 0:
        color = "yellow"
        headline = f"{high} high-severity alert{'s' if high != 1 else ''} to review when you get a chance."
    elif total > 0:
        color = "green"
        headline = f"All clear. {total} routine item{'s' if total != 1 else ''} in the queue."
    else:
        color = "green"
        headline = "All quiet. No pending alerts."

    return GlanceResponse(
        color=color,
        count=total,
        headline=headline,
        breakdown={"critical": critical, "high": high, "medium": medium, "low": low, "info": info},
        last_updated=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Feed — swipeable alert cards
# ---------------------------------------------------------------------------

@router.get("/feed", response_model=FeedResponse)
async def feed(
    limit: int = Query(10, ge=1, le=50),
    session: AsyncSession = Depends(get_session),
) -> FeedResponse:
    """Get the next batch of alert cards for the swipe feed."""

    severity_order = case(
        {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4},
        value=Alert.severity,
        else_=5,
    )

    # Undispositioned alerts, most urgent first
    stmt = (
        select(Alert)
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
        .order_by(severity_order, Alert.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    alerts = result.scalars().all()

    # Count remaining
    count_stmt = (
        select(func.count())
        .select_from(Alert)
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
    )
    total = await session.scalar(count_stmt) or 0
    remaining = max(0, total - len(alerts))

    cards = []
    for a in alerts:
        llm = a.llm_triage or {}
        raw = a.raw_event or {}
        source_ip = raw.get("data", {}).get("srcip") or raw.get("data", {}).get("src_ip")

        # Derive AI verdict: use LLM's explicit recommendation, or infer from confidence + benign
        ai_verdict = llm.get("recommended_verdict")
        ai_confidence = llm.get("confidence", 0.0)
        if not ai_verdict and not llm.get("degraded"):
            # Infer from confidence and benign explanations
            benign = llm.get("benign_explanations", [])
            if ai_confidence >= 0.7 and not benign:
                ai_verdict = "true_positive"
            elif ai_confidence < 0.3 or len(benign) >= 2:
                ai_verdict = "false_positive"
            elif ai_confidence >= 0.5:
                ai_verdict = "escalate"

        cards.append(FeedCard(
            id=a.id,
            severity=a.severity.value if isinstance(a.severity, Severity) else a.severity,
            title=a.rule_description or f"Rule {a.rule_id}",
            explanation=llm.get("explanation", "AI analysis unavailable — review the raw alert data."),
            ai_verdict=ai_verdict,
            ai_confidence=ai_confidence,
            agent=a.agent_name,
            source_ip=source_ip,
            timestamp=a.created_at,
            recommended_actions=llm.get("recommended_actions", []),
            controls=a.control_tags or [],
        ))

    return FeedResponse(cards=cards, remaining=remaining)


# ---------------------------------------------------------------------------
# Swipe — disposition via gesture
# ---------------------------------------------------------------------------

@router.post("/feed/{alert_id}/swipe", response_model=SwipeOut)
async def swipe(
    alert_id: uuid.UUID,
    body: SwipeIn,
    session: AsyncSession = Depends(get_session),
) -> SwipeOut:
    """Swipe to disposition an alert. Right=TP, Left=FP, Up=Escalate."""

    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Check existing disposition
    existing = await session.execute(
        select(AlertDisposition).where(AlertDisposition.alert_id == alert_id)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Already dispositioned")

    # Map swipe to verdict
    verdict_map = {
        "right": DispositionVerdict.TRUE_POSITIVE,
        "left": DispositionVerdict.FALSE_POSITIVE,
        "up": DispositionVerdict.UNDETERMINED,
    }
    verdict = verdict_map[body.direction]

    message_map = {
        "right": "Confirmed as true positive. Evidence recorded.",
        "left": "Marked as false positive. Pattern noted.",
        "up": "Escalated for deeper investigation.",
    }

    disposition = await record_disposition(
        alert_id=alert_id,
        verdict=verdict,
        analyst=body.analyst,
        notes=body.notes or f"Mobile swipe: {body.direction}",
        session=session,
    )

    # Award 1 XP for triaging any alert
    xp = XpEvent(analyst=body.analyst, points=1, reason="alert_triage", ref_id=alert_id)
    session.add(xp)

    # If true positive, create a ticket
    ticket_id = None
    if verdict == DispositionVerdict.TRUE_POSITIVE:
        ticket = Ticket(
            alert_id=alert_id,
            title=alert.rule_description or f"Rule {alert.rule_id}",
            severity=alert.severity.value if isinstance(alert.severity, Severity) else alert.severity,
            status=TicketStatus.OPEN,
            assigned_to=body.analyst,
        )
        session.add(ticket)
        await session.flush()
        ticket_id = ticket.id

    await session.commit()

    return SwipeOut(
        id=disposition.id,
        verdict=verdict.value,
        message=message_map[body.direction],
        xp_earned=1,
        ticket_id=ticket_id,
    )


# ---------------------------------------------------------------------------
# Score — gamification
# ---------------------------------------------------------------------------

@router.get("/score", response_model=ScoreResponse)
async def score(
    analyst: str = Query(default="mobile-user"),
    session: AsyncSession = Depends(get_session),
) -> ScoreResponse:
    """Get the analyst's security score, streak, and badges."""

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Alerts handled today
    today_count = await session.scalar(
        select(func.count())
        .select_from(AlertDisposition)
        .where(
            AlertDisposition.analyst == analyst,
            AlertDisposition.created_at >= today_start,
        )
    ) or 0

    # Total handled ever
    total_handled = await session.scalar(
        select(func.count())
        .select_from(AlertDisposition)
        .where(AlertDisposition.analyst == analyst)
    ) or 0

    # Pending alerts
    pending = await session.scalar(
        select(func.count())
        .select_from(Alert)
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
    ) or 0

    # Pending critical
    pending_critical = await session.scalar(
        select(func.count())
        .select_from(Alert)
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None), Alert.severity == Severity.CRITICAL)
    ) or 0

    # Calculate streak (consecutive days with at least one disposition)
    streak = 0
    check_date = today_start
    for _ in range(365):
        day_count = await session.scalar(
            select(func.count())
            .select_from(AlertDisposition)
            .where(
                AlertDisposition.analyst == analyst,
                AlertDisposition.created_at >= check_date,
                AlertDisposition.created_at < check_date + timedelta(days=1),
            )
        ) or 0
        if day_count > 0:
            streak += 1
            check_date -= timedelta(days=1)
        else:
            break

    # Average response time (alert created → disposition created)
    avg_resp = await session.execute(
        select(
            func.avg(
                func.extract("epoch", AlertDisposition.created_at) -
                func.extract("epoch", Alert.created_at)
            )
        )
        .select_from(AlertDisposition)
        .join(Alert)
        .where(AlertDisposition.analyst == analyst)
    )
    avg_seconds = avg_resp.scalar()
    avg_minutes = round(avg_seconds / 60, 1) if avg_seconds else None

    # Score calculation (0-100)
    # Factors: queue clearance, response time, streak, critical handling
    queue_score = max(0, 40 - pending * 2)  # Max 40 for clear queue
    streak_score = min(20, streak * 2)  # Max 20 for streak
    volume_score = min(20, today_count * 4)  # Max 20 for daily volume
    critical_penalty = pending_critical * 10  # -10 per pending critical
    score = max(0, min(100, queue_score + streak_score + volume_score + 20 - critical_penalty))

    # Trend (compare today vs yesterday)
    yesterday_start = today_start - timedelta(days=1)
    yesterday_count = await session.scalar(
        select(func.count())
        .select_from(AlertDisposition)
        .where(
            AlertDisposition.analyst == analyst,
            AlertDisposition.created_at >= yesterday_start,
            AlertDisposition.created_at < today_start,
        )
    ) or 0

    if today_count > yesterday_count:
        trend = "up"
    elif today_count < yesterday_count:
        trend = "down"
    else:
        trend = "steady"

    # Badges
    badges = []
    if total_handled >= 1:
        badges.append({"id": "first_response", "name": "First Responder", "description": "Handled your first alert"})
    if total_handled >= 100:
        badges.append({"id": "centurion", "name": "Centurion", "description": "100 alerts handled"})
    if streak >= 7:
        badges.append({"id": "week_warrior", "name": "Week Warrior", "description": "7-day streak"})
    if streak >= 30:
        badges.append({"id": "iron_wall", "name": "Iron Wall", "description": "30-day streak"})
    if pending_critical == 0 and total_handled > 0:
        badges.append({"id": "zero_critical", "name": "Zero Critical", "description": "No pending critical alerts"})
    if avg_minutes and avg_minutes < 15:
        badges.append({"id": "speed_demon", "name": "Speed Demon", "description": "Average response under 15 minutes"})

    # XP from database
    total_xp = await session.scalar(
        select(func.coalesce(func.sum(XpEvent.points), 0))
        .where(XpEvent.analyst == analyst)
    ) or 0

    # Open tickets
    open_tickets = await session.scalar(
        select(func.count())
        .select_from(Ticket)
        .where(
            Ticket.assigned_to == analyst,
            Ticket.status != TicketStatus.CLOSED,
        )
    ) or 0

    # Weekly summary
    week_start = today_start - timedelta(days=7)
    week_count = await session.scalar(
        select(func.count())
        .select_from(AlertDisposition)
        .where(
            AlertDisposition.analyst == analyst,
            AlertDisposition.created_at >= week_start,
        )
    ) or 0

    if week_count == 0:
        weekly_summary = "No alerts handled this week. Check your feed."
    elif avg_minutes and avg_minutes < 30:
        weekly_summary = f"{week_count} alerts handled this week with {avg_minutes}min avg response. Sharp."
    else:
        weekly_summary = f"{week_count} alerts handled this week. Keep it up."

    return ScoreResponse(
        score=score,
        xp=total_xp,
        streak_days=streak,
        alerts_handled_today=today_count,
        avg_response_minutes=avg_minutes,
        trend=trend,
        badges=badges,
        weekly_summary=weekly_summary,
        open_tickets=open_tickets,
    )


# ---------------------------------------------------------------------------
# Coach — learn from what you just handled
# ---------------------------------------------------------------------------

@router.get("/coach/{alert_id}", response_model=CoachResponse)
async def coach(
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> CoachResponse:
    """Get a micro-lesson about an alert you just handled."""

    stmt = (
        select(Alert)
        .options(selectinload(Alert.disposition))
        .where(Alert.id == alert_id)
    )
    result = await session.execute(stmt)
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    llm = alert.llm_triage or {}
    severity = alert.severity.value if isinstance(alert.severity, Severity) else alert.severity
    controls = alert.control_tags or []

    # Build lesson based on alert type and LLM analysis
    explanation = llm.get("explanation", "")
    benign = llm.get("benign_explanations", [])
    actions = llm.get("recommended_actions", [])

    # Determine attack category from rule description
    desc_lower = (alert.rule_description or "").lower()
    if any(w in desc_lower for w in ["brute", "authentication", "login", "password"]):
        category = "Credential Attack"
        lesson_title = "Understanding Credential Attacks"
        lesson_body = (
            f"This alert (Rule {alert.rule_id}) detected a potential credential attack on "
            f"{alert.agent_name or 'a system'}. "
            f"{explanation} "
            f"Credential attacks are among the most common initial access techniques. "
            f"Attackers try common passwords, leaked credentials, or automated tools to gain access. "
            f"Your response helps build the evidence trail that proves your organization monitors for and responds to these threats."
        )
        next_tip = "Check if MFA is enabled on all external-facing accounts."
    elif any(w in desc_lower for w in ["malware", "trojan", "virus", "ransomware"]):
        category = "Malware"
        lesson_title = "Malware Detection and Response"
        lesson_body = (
            f"Rule {alert.rule_id} flagged potential malware activity on {alert.agent_name or 'a system'}. "
            f"{explanation} "
            f"Early detection is critical — the faster you identify and contain malware, "
            f"the less damage it can do. Your triage of this alert is evidence of your "
            f"organization's malware defense capability."
        )
        next_tip = "Verify endpoint protection is active on the affected host."
    elif any(w in desc_lower for w in ["file", "integrity", "modified", "changed"]):
        category = "File Integrity"
        lesson_title = "File Integrity Monitoring"
        lesson_body = (
            f"This alert detected a file change on {alert.agent_name or 'a system'}. "
            f"{explanation} "
            f"File integrity monitoring (FIM) catches unauthorized changes to critical files. "
            f"Not every change is malicious — system updates trigger these too. "
            f"Your job is to determine if this change was expected."
        )
        next_tip = "Review if any maintenance windows were scheduled for this host."
    else:
        category = "Security Event"
        lesson_title = f"Security Event: {alert.rule_description[:60]}"
        lesson_body = (
            f"Rule {alert.rule_id} on {alert.agent_name or 'a system'}: {explanation} "
            f"Every alert you review strengthens your security posture. "
            f"The evidence chain records your response, building compliance documentation automatically."
        )
        next_tip = "Review related alerts from the same host in the investigation tab."

    if benign:
        lesson_body += f" Note: possible benign explanations include {', '.join(benign[:2])}."

    # Map controls to human-readable
    control_descriptions = {
        "3.3.1": "NIST 800-171: Audit Logging",
        "3.3.2": "NIST 800-171: User Attribution",
        "3.6.1": "NIST 800-171: Incident Handling",
        "3.6.2": "NIST 800-171: Incident Reporting",
        "3.14.6": "NIST 800-171: System Monitoring",
    }
    controls_satisfied = [control_descriptions.get(c, c) for c in controls[:5]]

    return CoachResponse(
        lesson_title=lesson_title,
        lesson_body=lesson_body,
        duration_seconds=30,
        controls_satisfied=controls_satisfied,
        next_tip=next_tip,
    )


# ---------------------------------------------------------------------------
# Tickets — confirmed alerts that need resolution
# ---------------------------------------------------------------------------

XP_BY_SEVERITY = {"critical": 100, "high": 50, "medium": 25, "low": 10, "info": 10}


class TicketOut(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    title: str
    severity: str
    status: str
    assigned_to: str
    closed_by: str | None
    resolution_notes: str | None
    created_at: datetime


class TicketCloseIn(BaseModel):
    analyst: str = Field(default="mobile-user", min_length=1, max_length=255)
    resolution_notes: str = Field(default="", max_length=2000)


class TicketCloseOut(BaseModel):
    id: uuid.UUID
    status: str
    xp_earned: int
    message: str


@router.get("/tickets", response_model=list[TicketOut])
async def list_tickets(
    status: str = Query(default="open"),
    analyst: str = Query(default=""),
    session: AsyncSession = Depends(get_session),
) -> list[TicketOut]:
    """List tickets, optionally filtered by status and analyst."""
    stmt = select(Ticket).order_by(Ticket.created_at.desc())

    if status == "open":
        stmt = stmt.where(Ticket.status != TicketStatus.CLOSED)
    elif status == "closed":
        stmt = stmt.where(Ticket.status == TicketStatus.CLOSED)

    if analyst:
        stmt = stmt.where(Ticket.assigned_to == analyst)

    result = await session.execute(stmt.limit(50))
    tickets = result.scalars().all()
    return [_ticket_out(t) for t in tickets]


@router.post("/tickets/{ticket_id}/close", response_model=TicketCloseOut)
async def close_ticket(
    ticket_id: uuid.UUID,
    body: TicketCloseIn,
    session: AsyncSession = Depends(get_session),
) -> TicketCloseOut:
    """Close a ticket and award XP based on severity."""
    ticket = await session.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(409, "Ticket already closed")

    ticket.status = TicketStatus.CLOSED
    ticket.closed_by = body.analyst
    ticket.resolution_notes = body.resolution_notes

    # Award XP by severity
    xp_amount = XP_BY_SEVERITY.get(ticket.severity, 10)
    xp = XpEvent(
        analyst=body.analyst,
        points=xp_amount,
        reason="ticket_closed",
        ref_id=ticket_id,
    )
    session.add(xp)
    await session.commit()

    return TicketCloseOut(
        id=ticket.id,
        status="closed",
        xp_earned=xp_amount,
        message=f"Ticket closed. +{xp_amount} XP!",
    )


@router.patch("/tickets/{ticket_id}/assign")
async def assign_ticket(
    ticket_id: uuid.UUID,
    analyst: str = Query(...),
    session: AsyncSession = Depends(get_session),
):
    """Reassign a ticket."""
    ticket = await session.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    ticket.assigned_to = analyst
    await session.commit()
    return _ticket_out(ticket)


def _ticket_out(t: Ticket) -> TicketOut:
    return TicketOut(
        id=t.id,
        alert_id=t.alert_id,
        title=t.title,
        severity=t.severity,
        status=t.status.value,
        assigned_to=t.assigned_to,
        closed_by=t.closed_by,
        resolution_notes=t.resolution_notes,
        created_at=t.created_at,
    )
