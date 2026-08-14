"""Investigation query engine — orchestrates context gathering and LLM response."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.ollama import OllamaClient
from kahu.services.investigation.context import (
    gather_from_indexer,
    gather_from_postgres,
    parse_question,
)
from kahu.services.investigation.session import (
    get_or_create_session,
)

log = logging.getLogger("kahu.investigation.query")

SYSTEM_PROMPT = """You are Kahu, an on-premises AI security analyst assistant.
You help analysts investigate alerts, hunt for threats, and understand their security environment.
You have access to real alert data from the organization's SIEM (Wazuh) and triaged alert database.

Rules:
- Be concise and direct. Analysts are busy.
- Reference specific data when answering: rule IDs, hostnames, IPs, timestamps.
- If you see patterns (repeated source IPs, targeted hosts, escalation chains), call them out.
- Suggest concrete next investigation steps when relevant.
- If you don't have enough data to answer confidently, say so and suggest what data to look for.
- Never invent data that isn't in the context provided.
- When comparing or correlating events, note the time relationships.
- If the analyst is following up on a previous question, use conversation history for continuity."""


async def investigate(
    question: str,
    db_session: AsyncSession,
    session_id: str | None = None,
) -> dict:
    """Run a full investigation query: parse → gather → generate → respond."""
    # Get or create conversation session
    inv_session = get_or_create_session(session_id)
    inv_session.add_analyst_turn(question)

    # Parse the question for structured hints
    hints = parse_question(question)

    # Gather context from both sources in parallel-ish fashion
    pg_context = await gather_from_postgres(db_session, hints)
    indexer_context = await gather_from_indexer(hints)

    # Merge and deduplicate (prefer postgres for triaged alerts, indexer for raw logs)
    all_context = pg_context + indexer_context
    total_context = len(all_context)

    # Format for the LLM
    context_text = _format_context(pg_context, indexer_context)
    history_text = inv_session.format_history()

    prompt_parts = []
    if history_text:
        # Only include prior turns, not the current question (it's already the last turn)
        prior_turns = "\n".join(
            f"{'Analyst' if t.role == 'analyst' else 'Kahu'}: {t.content}"
            for t in inv_session.history[:-1]
        )
        if prior_turns:
            prompt_parts.append(f"Conversation so far:\n{prior_turns}")

    prompt_parts.append(f"Alert and log data from the environment:\n{context_text}")
    prompt_parts.append(f"Analyst question: {question}")
    prompt_parts.append("Answer the analyst's question based on the data above.")

    prompt = "\n\n".join(prompt_parts)

    # Generate response
    ollama = OllamaClient()
    degraded = False
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        response = await ollama.generate(prompt=prompt, system=SYSTEM_PROMPT)
        response = response.strip()
    except Exception:
        response = _fallback_response(question, hints, pg_context, indexer_context)
        degraded = True

    inv_session.add_kahu_turn(response, context_count=total_context)

    return {
        "response": response,
        "session_id": inv_session.id,
        "context_used": total_context,
        "context_sources": {
            "postgres": len(pg_context),
            "wazuh_indexer": len(indexer_context),
        },
        "filters_applied": {k: str(v) for k, v in hints.items()},
        "degraded": degraded,
    }


async def get_timeline(
    db_session: AsyncSession,
    target: str,
    hours: int = 24,
) -> dict:
    """Build an event timeline for a specific host or IP."""
    hints = parse_question(f"last {hours} hours {target}")
    # Also try as a direct host/IP
    if not hints.get("ips") and not hints.get("hosts"):
        if "." in target and all(p.isdigit() for p in target.split(".")):
            hints["ips"] = [target]
        else:
            hints["hosts"] = [target]

    pg_events = await gather_from_postgres(db_session, hints, limit=100)
    indexer_events = await gather_from_indexer(hints, limit=100)

    # Merge and sort by time
    all_events = []
    for e in pg_events:
        all_events.append(
            {
                "time": e.get("created_at", ""),
                "source": "triaged",
                "severity": e.get("severity", ""),
                "rule_id": e.get("rule_id", ""),
                "description": e.get("rule_description", ""),
                "agent": e.get("agent_name", ""),
                "src_ip": e.get("source_ip", ""),
                "verdict": e.get("verdict"),
            }
        )
    for e in indexer_events:
        all_events.append(
            {
                "time": e.get("timestamp", ""),
                "source": "raw_log",
                "severity_level": e.get("rule_level", 0),
                "rule_id": e.get("rule_id", ""),
                "description": e.get("rule_description", ""),
                "agent": e.get("agent_name", ""),
                "src_ip": e.get("source_ip", ""),
                "log_excerpt": e.get("full_log", ""),
            }
        )

    all_events.sort(key=lambda x: x.get("time", ""), reverse=True)

    return {
        "target": target,
        "hours": hours,
        "event_count": len(all_events),
        "events": all_events,
    }


def _format_context(pg_alerts: list[dict], indexer_hits: list[dict]) -> str:
    """Format combined context for the LLM prompt."""
    if not pg_alerts and not indexer_hits:
        return "No matching alerts or logs found for the given criteria."

    sections = []

    if pg_alerts:
        lines = [f"=== Triaged Alerts ({len(pg_alerts)} results) ==="]
        for a in pg_alerts:
            parts = [
                f"[{a['severity'].upper()}]",
                f"Rule {a['rule_id']}:",
                a["rule_description"][:120],
                f"| host={a['agent_name'] or '?'}",
            ]
            if a.get("source_ip"):
                parts.append(f"src={a['source_ip']}")
            if a.get("dest_ip"):
                parts.append(f"dst={a['dest_ip']}")
            parts.append(f"| {a['created_at']}")
            if a.get("verdict"):
                parts.append(f"| verdict={a['verdict']}")
            if a.get("ai_explanation"):
                parts.append(f"| AI: {a['ai_explanation'][:150]}")
            lines.append(" ".join(parts))
        sections.append("\n".join(lines))

    if indexer_hits:
        lines = [f"=== Raw Wazuh Logs ({len(indexer_hits)} results) ==="]
        for h in indexer_hits:
            parts = [
                f"[level={h['rule_level']}]",
                f"Rule {h['rule_id']}:",
                h["rule_description"][:120],
                f"| host={h['agent_name'] or '?'}",
            ]
            if h.get("source_ip"):
                parts.append(f"src={h['source_ip']}")
            if h.get("dest_ip"):
                parts.append(f"dst={h['dest_ip']}")
            parts.append(f"| {h['timestamp']}")
            if h.get("full_log"):
                parts.append(f"| log: {h['full_log'][:200]}")
            lines.append(" ".join(parts))
        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def _fallback_response(
    question: str,
    hints: dict,
    pg_alerts: list[dict],
    indexer_hits: list[dict],
) -> str:
    """Generate a deterministic response when Ollama is offline."""
    total = len(pg_alerts) + len(indexer_hits)
    if total == 0:
        return (
            "The AI model is offline, so I can't interpret your question — "
            "but I also found no matching alerts or logs for the filters I extracted. "
            "Try being more specific with hostnames, IPs, or time ranges."
        )

    parts = [
        f"The AI model is offline, but I found {total} matching events "
        f"({len(pg_alerts)} triaged alerts, {len(indexer_hits)} raw logs)."
    ]

    # Provide basic stats
    if pg_alerts:
        sevs = {}
        for a in pg_alerts:
            s = a.get("severity", "unknown")
            sevs[s] = sevs.get(s, 0) + 1
        parts.append(f"Severity breakdown: {sevs}")

        hosts = set(a.get("agent_name") for a in pg_alerts if a.get("agent_name"))
        if hosts:
            parts.append(f"Affected hosts: {', '.join(sorted(hosts))}")

        ips = set(a.get("source_ip") for a in pg_alerts if a.get("source_ip"))
        if ips:
            parts.append(f"Source IPs: {', '.join(sorted(ips))}")

    parts.append("Reconnect Ollama for full natural-language analysis.")
    return " ".join(parts)
