"""Security briefing API — AI-generated status summary on login."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kuahene.clients.ollama import OllamaClient
from kuahene.db import get_session
from kuahene.models.alerts import Alert, AlertDisposition, Severity

router = APIRouter()

BRIEFING_SYSTEM = """You are Kuahene, an on-premises AI security operations assistant.
You are greeting an analyst who just logged in. Give a brief, direct security status briefing.
Be conversational but professional — like a senior SOC analyst handing off a shift.
Keep it to 3-5 sentences max. If there are critical issues, lead with those.
If everything is quiet, say so and mention what's been handled.
Do NOT use bullet points or markdown. Speak naturally."""


@router.get("/briefing")
async def get_briefing(session: AsyncSession = Depends(get_session)) -> dict:
    """Generate an AI security briefing based on current state."""

    # Gather context
    # 1. Undispositioned alerts by severity
    stmt = (
        select(Alert.severity, func.count())
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
        .group_by(Alert.severity)
    )
    result = await session.execute(stmt)
    pending_by_sev = {row[0].value if isinstance(row[0], Severity) else row[0]: row[1] for row in result.all()}

    # 2. Total dispositioned today-ish (recent)
    disp_count_result = await session.scalar(select(func.count()).select_from(AlertDisposition))
    disp_count = disp_count_result or 0

    # 3. Total alerts
    total_alerts = await session.scalar(select(func.count()).select_from(Alert)) or 0

    # 4. Most recent critical alert
    recent_critical = await session.execute(
        select(Alert.rule_description, Alert.agent_name, Alert.created_at)
        .where(Alert.severity == Severity.CRITICAL)
        .order_by(Alert.created_at.desc())
        .limit(1)
    )
    latest_critical = recent_critical.first()

    # Build context for LLM
    pending_total = sum(pending_by_sev.values())
    critical_count = pending_by_sev.get("critical", 0)
    high_count = pending_by_sev.get("high", 0)

    context_parts = [
        f"Current queue: {pending_total} undispositioned alerts.",
        f"Breakdown: {critical_count} critical, {high_count} high, {pending_by_sev.get('medium', 0)} medium, {pending_by_sev.get('low', 0)} low, {pending_by_sev.get('info', 0)} info.",
        f"Total alerts processed: {total_alerts}. Dispositioned so far: {disp_count}.",
    ]

    if latest_critical:
        context_parts.append(
            f"Most recent critical alert: \"{latest_critical[0]}\" on host {latest_critical[1] or 'unknown'} at {latest_critical[2]}."
        )

    # Get real vuln data from DB
    try:
        from kuahene.models.vulnerabilities import VulnFinding, FindingStatus
        vuln_result = await session.execute(
            select(VulnFinding.severity, func.count())
            .where(VulnFinding.status == FindingStatus.OPEN)
            .group_by(VulnFinding.severity)
        )
        vuln_counts = {row[0]: row[1] for row in vuln_result.all()}
        total_vulns = sum(vuln_counts.values())
        if total_vulns > 0:
            crit_vulns = vuln_counts.get("critical", 0)
            context_parts.append(f"Vulnerability posture: {total_vulns} open findings ({crit_vulns} critical).")
    except Exception:
        pass

    context = " ".join(context_parts)
    prompt = f"Security context: {context}\n\nGive the analyst their shift briefing."

    # Generate with Ollama
    ollama = OllamaClient()
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        response = await ollama.generate(prompt=prompt, system=BRIEFING_SYSTEM)
        return {
            "briefing": response.strip(),
            "context": {
                "pending_alerts": pending_total,
                "critical": critical_count,
                "high": high_count,
                "total_processed": total_alerts,
                "dispositioned": disp_count,
            },
            "degraded": False,
        }
    except Exception:
        # Fallback — deterministic briefing
        if critical_count > 0:
            fallback = f"Heads up — you have {critical_count} critical and {high_count} high-severity alerts pending review. The most recent is on {latest_critical[1] if latest_critical else 'an unknown host'}. I'd start there."
        elif pending_total > 0:
            fallback = f"Things are mostly calm. You have {pending_total} alerts in the queue, nothing critical. Routine review recommended."
        else:
            fallback = "All quiet. No pending alerts in the queue. All systems operational."

        return {
            "briefing": fallback,
            "context": {
                "pending_alerts": pending_total,
                "critical": critical_count,
                "high": high_count,
                "total_processed": total_alerts,
                "dispositioned": disp_count,
            },
            "degraded": True,
        }
