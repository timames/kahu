"""Report generation — LLM-assisted narrative reports from structured data."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.ollama import OllamaClient
from kahu.services.reporting.data import (
    get_alert_summary,
    get_evidence_summary,
    get_incident_data,
)

log = logging.getLogger("kahu.reporting.generator")

EXECUTIVE_SYSTEM = """You are Kahu, writing an executive security briefing for non-technical leadership.

Rules:
- Lead with risk posture: are things getting better or worse?
- Use plain language — no jargon, no acronyms without explanation.
- Quantify: use the numbers provided. Don't round excessively.
- Highlight what was handled (dispositioned) vs what needs attention (pending).
- If there are critical findings, explain the business impact in one sentence.
- Keep it to 2-4 short paragraphs. Executives skim.
- End with 1-2 concrete recommendations, not vague advice."""

INCIDENT_SYSTEM = """You are Kahu, writing an incident report for the security operations team.

Rules:
- Structure: Summary → Timeline → Impact → Indicators → Response → Recommendations
- Be precise with timestamps, IPs, hostnames, and rule IDs.
- Describe the attack chain if one is apparent from the timeline.
- Note what was detected vs what might have been missed.
- Include IOCs (IPs, patterns) that should be watched going forward.
- Be direct about severity — don't soften critical findings.
- Keep it professional and factual."""

EVIDENCE_SYSTEM = """You are Kahu, writing a compliance evidence summary for auditors.

Rules:
- State the time period covered and total evidence records generated.
- Summarize by evidence type (what controls were exercised).
- Note whether the hash chain is intact (critical for evidence integrity).
- If chain breaks are detected, flag them prominently.
- Reference specific control tags where relevant.
- Keep language formal — this may be presented to regulators.
- Be concise but thorough."""


async def generate_executive_report(
    session: AsyncSession,
    since: datetime,
    until: datetime | None = None,
) -> dict:
    """Generate an LLM-assisted executive summary report."""
    until = until or datetime.now(timezone.utc)
    data = await get_alert_summary(session, since, until)

    prompt = f"""Security operations data for the reporting period:

Total alerts: {data['total_alerts']}
By severity: {data['by_severity']}
Disposition rate: {data['disposition_rate']}%
Pending review: {data['pending']}
Dispositioned: {data['disposed']}
Disposition breakdown: {data['by_disposition']}

Top triggered rules:
{_format_top_items(data['top_rules'], 'rule_id', 'description', 'count')}

Top source IPs:
{_format_top_items(data['top_source_ips'], 'ip', count_key='count')}

Most targeted hosts:
{_format_top_items(data['top_hosts'], 'host', count_key='count')}

Write the executive briefing."""

    narrative = await _generate_or_fallback(
        prompt, EXECUTIVE_SYSTEM, _executive_fallback(data)
    )

    return {
        "report_type": "executive",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": data["period"],
        "narrative": narrative["text"],
        "data": data,
        "degraded": narrative["degraded"],
    }


async def generate_incident_report(
    session: AsyncSession,
    alert_ids: list[str],
    title: str = "",
) -> dict:
    """Generate an LLM-assisted incident report from a set of related alerts."""
    data = await get_incident_data(session, alert_ids)

    if "error" in data:
        return data

    timeline_text = "\n".join(
        f"  {e['timestamp']} | [{e['severity'].upper()}] Rule {e['rule_id']}: "
        f"{e['rule_description'][:100]} | host={e['agent_name']} "
        f"src={e.get('source_ip', '?')} dst={e.get('dest_ip', '?')}"
        + (f" | AI: {e['ai_explanation'][:100]}" if e.get("ai_explanation") else "")
        + (f" | Verdict: {e['verdict']}" if e.get("verdict") else "")
        for e in data["timeline"]
    )

    prompt = f"""Incident data:

Title: {title or 'Security Incident'}
Overall severity: {data['overall_severity']}
Alert count: {data['alert_count']}
Time span: {data['time_range']['first']} to {data['time_range']['last']}
Affected hosts: {', '.join(data['affected_hosts']) or 'unknown'}
Involved IPs: {', '.join(data['involved_ips']) or 'none identified'}

Event timeline:
{timeline_text}

Write the incident report."""

    narrative = await _generate_or_fallback(
        prompt, INCIDENT_SYSTEM, _incident_fallback(data, title)
    )

    return {
        "report_type": "incident",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "title": title or "Security Incident",
        "narrative": narrative["text"],
        "data": data,
        "degraded": narrative["degraded"],
    }


async def generate_evidence_package(
    session: AsyncSession,
    since: datetime,
    until: datetime | None = None,
) -> dict:
    """Generate a compliance evidence package with narrative summary."""
    until = until or datetime.now(timezone.utc)
    data = await get_evidence_summary(session, since, until)

    prompt = f"""Compliance evidence data:

Period: {data['period']['since']} to {data['period']['until']}
Total evidence records: {data['total_records']}
By event type: {data['by_event_type']}
Hash chain integrity: {'INTACT' if data['chain_intact'] else 'BROKEN — EVIDENCE TAMPERING POSSIBLE'}

Write the compliance evidence summary."""

    narrative = await _generate_or_fallback(
        prompt, EVIDENCE_SYSTEM, _evidence_fallback(data)
    )

    return {
        "report_type": "evidence_package",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": data["period"],
        "narrative": narrative["text"],
        "chain_intact": data["chain_intact"],
        "summary": {
            "total_records": data["total_records"],
            "by_event_type": data["by_event_type"],
        },
        "records": data["records"],
        "degraded": narrative["degraded"],
    }


async def _generate_or_fallback(
    prompt: str, system: str, fallback: str
) -> dict:
    """Try LLM generation, fall back to deterministic text."""
    ollama = OllamaClient()
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        text = await ollama.generate(prompt=prompt, system=system)
        return {"text": text.strip(), "degraded": False}
    except Exception:
        return {"text": fallback, "degraded": True}


def _format_top_items(
    items: list[dict],
    key: str,
    desc_key: str | None = None,
    count_key: str = "count",
) -> str:
    if not items:
        return "  (none)"
    lines = []
    for item in items:
        parts = [f"  {item[key]}"]
        if desc_key and item.get(desc_key):
            parts.append(f"— {item[desc_key][:60]}")
        parts.append(f"({item[count_key]})")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def _executive_fallback(data: dict) -> str:
    """Deterministic executive summary when LLM is offline."""
    total = data["total_alerts"]
    if total == 0:
        return "No alerts were recorded during this reporting period."

    critical = data["by_severity"].get("critical", 0)
    high = data["by_severity"].get("high", 0)
    rate = data["disposition_rate"]

    parts = [
        f"During this period, {total} security alerts were generated.",
        f"{critical} were critical severity and {high} were high severity.",
        f"The team dispositioned {rate}% of alerts, with {data['pending']} still pending review.",
    ]

    if critical > 0:
        parts.append("Immediate attention is required for the outstanding critical alerts.")

    if rate < 50:
        parts.append(
            "The disposition rate is below 50%, indicating the team may need "
            "additional resources or alert tuning to keep up with volume."
        )

    return " ".join(parts)


def _incident_fallback(data: dict, title: str) -> str:
    """Deterministic incident report when LLM is offline."""
    parts = [
        f"Incident: {title or 'Security Incident'}",
        f"Severity: {data['overall_severity'].upper()}",
        f"Alert count: {data['alert_count']}",
        f"Time span: {data['time_range']['first']} to {data['time_range']['last']}",
        f"Affected hosts: {', '.join(data['affected_hosts']) or 'unknown'}",
        f"Involved IPs: {', '.join(data['involved_ips']) or 'none identified'}",
        "",
        "AI-generated narrative unavailable — Ollama is offline. "
        "Review the timeline data in the attached structured report.",
    ]
    return "\n".join(parts)


def _evidence_fallback(data: dict) -> str:
    """Deterministic evidence summary when LLM is offline."""
    chain_status = "intact" if data["chain_intact"] else "BROKEN"
    return (
        f"Evidence package covering {data['period']['since']} to {data['period']['until']}. "
        f"{data['total_records']} records generated across {len(data['by_event_type'])} event types. "
        f"Hash chain integrity: {chain_status}."
    )
