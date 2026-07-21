"""Natural-language investigation API — ask questions about alerts and security posture."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.ollama import OllamaClient
from kahu.db import get_session
from kahu.models.alerts import Alert, AlertDisposition, Severity

router = APIRouter()

INVESTIGATION_SYSTEM = """You are Kahu, an on-premises AI security analyst assistant.
You help analysts investigate alerts and understand their security environment.
You have access to real alert data from the organization's SIEM (Wazuh).

Rules:
- Be concise and direct. Analysts are busy.
- Reference specific alert data when answering (rule IDs, hostnames, IPs, timestamps).
- If you see patterns (repeated source IPs, targeted hosts, escalation chains), call them out.
- Suggest next investigation steps when relevant.
- If you don't have enough data to answer confidently, say so.
- Never invent data that isn't in the context provided.
- Use plain language, not bullet points unless listing multiple items."""


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    response: str
    context_used: int
    degraded: bool = False


@router.post("/query", response_model=ChatResponse)
async def investigate(
    body: ChatMessage,
    session: AsyncSession = Depends(get_session),
) -> ChatResponse:
    """Ask a natural-language question about alerts and security posture."""

    # Gather relevant alert context based on the question
    context_alerts = await _gather_context(body.message, session)

    # Build prompt with alert context
    context_text = _format_alert_context(context_alerts)
    prompt = f"""Alert data from the environment:
{context_text}

Analyst question: {body.message}

Answer the analyst's question based on the alert data above."""

    ollama = OllamaClient()
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        response = await ollama.generate(prompt=prompt, system=INVESTIGATION_SYSTEM)
        return ChatResponse(
            response=response.strip(),
            context_used=len(context_alerts),
            degraded=False,
        )
    except Exception:
        return ChatResponse(
            response="I'm unable to process your question right now — the AI model is offline. Check the Services tab for pipeline status.",
            context_used=0,
            degraded=True,
        )


async def _gather_context(question: str, session: AsyncSession) -> list[dict]:
    """Pull relevant alerts to use as context for the question."""
    q_lower = question.lower()

    # Start with recent undispositioned alerts (most relevant)
    stmt = (
        select(Alert)
        .outerjoin(AlertDisposition)
        .where(AlertDisposition.id.is_(None))
        .order_by(Alert.created_at.desc())
        .limit(30)
    )

    # If question mentions specific terms, try to filter
    if "critical" in q_lower:
        stmt = (
            select(Alert)
            .where(Alert.severity == Severity.CRITICAL)
            .order_by(Alert.created_at.desc())
            .limit(30)
        )
    elif "high" in q_lower:
        stmt = (
            select(Alert)
            .where(Alert.severity.in_([Severity.CRITICAL, Severity.HIGH]))
            .order_by(Alert.created_at.desc())
            .limit(30)
        )

    result = await session.execute(stmt)
    alerts = result.scalars().all()

    # Convert to dicts for context
    context = []
    for a in alerts:
        llm = a.llm_triage or {}
        context.append({
            "severity": a.severity.value if isinstance(a.severity, Severity) else a.severity,
            "rule_id": a.rule_id,
            "rule_description": a.rule_description,
            "agent_name": a.agent_name,
            "created_at": str(a.created_at),
            "ai_explanation": llm.get("explanation", ""),
            "source_ip": (a.raw_event or {}).get("data", {}).get("srcip", ""),
        })

    return context


def _format_alert_context(alerts: list[dict]) -> str:
    """Format alerts into a compact text context for the LLM."""
    if not alerts:
        return "No alerts currently in the system."

    lines = []
    for i, a in enumerate(alerts, 1):
        parts = [
            f"[{a['severity'].upper()}]",
            f"Rule {a['rule_id']}:",
            a["rule_description"][:100],
            f"| host={a['agent_name'] or '?'}",
        ]
        if a.get("source_ip"):
            parts.append(f"src={a['source_ip']}")
        parts.append(f"| {a['created_at']}")
        if a.get("ai_explanation"):
            parts.append(f"| AI: {a['ai_explanation'][:150]}")
        lines.append(" ".join(parts))

    return "\n".join(lines)
