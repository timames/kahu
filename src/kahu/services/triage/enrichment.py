"""Stage 2 — Alert enrichment with asset context, related events, vuln state.

Correlated alert groups are enriched with asset context, recent related events,
vulnerability state of involved hosts, and historical disposition of similar
alerts on this deployment.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.redaction import redact_secrets
from kahu.clients.wazuh import WazuhIndexerClient
from kahu.models.alerts import Alert, AlertDisposition, Severity
from kahu.services.triage.disposition import AI_ANALYST

logger = logging.getLogger(__name__)

RELATED_EVENT_WINDOW_MINUTES = 15
MAX_RELATED_EVENTS = 50
MAX_HISTORICAL_DISPOSITIONS = 100


@dataclass
class EnrichedAlert:
    data: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    prompt_hash: str = ""
    redacted_prompt_text: str = ""


async def enrich_alert_group(
    alert: dict,
    session: AsyncSession | None = None,
    indexer: WazuhIndexerClient | None = None,
) -> EnrichedAlert:
    """Enrich a filtered alert with context for LLM triage."""
    sources: list[str] = ["alert_data"]

    agent_name = alert.get("agent", {}).get("name", "unknown")
    rule_id = str(alert.get("rule", {}).get("id", ""))
    timestamp_str = alert.get("timestamp", "")

    # --- Asset context (from alert's agent metadata) ---
    asset_context = _extract_asset_context(alert)
    if asset_context:
        sources.append("asset_context")

    # --- Related events from Wazuh indexer ---
    related_events = await _fetch_related_events(agent_name, timestamp_str, indexer)
    if related_events:
        sources.append("related_events")

    # --- Vulnerability state for the agent ---
    vuln_state = await _fetch_vuln_state(agent_name, indexer)
    if vuln_state:
        sources.append("vuln_state")

    # --- Historical dispositions of same rule from Postgres ---
    rule_history = await _fetch_historical_dispositions(rule_id, session)
    if rule_history:
        sources.append("rule_history")

    # --- Agent-level disposition history ---
    agent_history = await _fetch_agent_history(agent_name, session)
    if agent_history:
        sources.append("agent_history")

    enriched_data = {
        "alert": alert,
        "asset_context": asset_context,
        "related_events": related_events,
        "vuln_state": vuln_state,
        "rule_history": rule_history,
        "agent_history": agent_history,
    }

    # Build the redacted text representation for prompt assembly
    prompt_text = json.dumps(enriched_data, sort_keys=True, default=str)
    redacted_text = redact_secrets(prompt_text)
    prompt_hash = hashlib.sha256(redacted_text.encode()).hexdigest()[:16]

    return EnrichedAlert(
        data=enriched_data,
        sources=sources,
        prompt_hash=prompt_hash,
        redacted_prompt_text=redacted_text,
    )


def _extract_asset_context(alert: dict) -> dict:
    """Pull asset metadata from the alert's agent and syscheck fields."""
    agent = alert.get("agent", {})
    context: dict = {}

    if agent.get("name"):
        context["hostname"] = agent["name"]
    if agent.get("ip"):
        context["ip"] = agent["ip"]
    if agent.get("os", {}).get("name"):
        context["os"] = agent["os"]["name"]
    if agent.get("os", {}).get("version"):
        context["os_version"] = agent["os"]["version"]

    # SCA / config assessment context if present
    sca = alert.get("data", {}).get("sca", {})
    if sca:
        context["sca_policy"] = sca.get("policy", "")
        context["sca_check"] = sca.get("check", {}).get("title", "")

    return context


async def _fetch_related_events(
    agent_name: str,
    timestamp_str: str,
    indexer: WazuhIndexerClient | None,
) -> list[dict]:
    """Query Wazuh indexer for recent events from the same agent."""
    if indexer is None:
        return []

    try:
        ts = _parse_wazuh_timestamp(timestamp_str)
    except (ValueError, TypeError):
        ts = datetime.now(tz=UTC)

    window_start = ts - timedelta(minutes=RELATED_EVENT_WINDOW_MINUTES)
    window_end = ts + timedelta(minutes=5)

    query = {
        "size": MAX_RELATED_EVENTS,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.name": agent_name}},
                    {
                        "range": {
                            "timestamp": {
                                "gte": window_start.isoformat(),
                                "lte": window_end.isoformat(),
                            }
                        }
                    },
                ],
                "filter": [{"range": {"rule.level": {"gte": 3}}}],
            }
        },
        "_source": [
            "timestamp",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "data",
            "location",
        ],
    }

    try:
        result = await indexer.search(index="wazuh-alerts-*", query=query)
        hits = result.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception:
        logger.warning("Failed to fetch related events from indexer", exc_info=True)
        return []


async def _fetch_vuln_state(
    agent_name: str,
    indexer: WazuhIndexerClient | None,
) -> dict:
    """Get vulnerability summary for the agent from the Wazuh vuln index."""
    if indexer is None:
        return {}

    query = {
        "size": 0,
        "query": {"match": {"agent.name": agent_name}},
        "aggs": {
            "by_severity": {"terms": {"field": "data.vulnerability.severity", "size": 5}},
            "critical_cves": {
                "filter": {"terms": {"data.vulnerability.severity": ["Critical", "High"]}},
                "aggs": {
                    "cves": {
                        "terms": {
                            "field": "data.vulnerability.cve",
                            "size": 10,
                        }
                    }
                },
            },
        },
    }

    try:
        result = await indexer.search(index="wazuh-states-vulnerabilities-*", query=query)
        aggs = result.get("aggregations", {})
        severity_buckets = aggs.get("by_severity", {}).get("buckets", [])
        critical_cves = aggs.get("critical_cves", {}).get("cves", {}).get("buckets", [])

        return {
            "severity_counts": {b["key"]: b["doc_count"] for b in severity_buckets},
            "critical_cves": [b["key"] for b in critical_cves],
        }
    except Exception:
        logger.warning("Failed to fetch vuln state from indexer", exc_info=True)
        return {}


async def _fetch_historical_dispositions(
    rule_id: str,
    session: AsyncSession | None,
) -> dict:
    """Compute aggregate disposition stats for this rule_id.

    Returns a dict with total count, verdict breakdown, false positive rate,
    and recent examples — giving the LLM a strong statistical signal.

    HUMAN dispositions only. The prompt tells the model this history is its
    strongest signal, so kahu-ai's own auto-dispositions must not appear here:
    with them included, a burst of auto-confirms filled the recent window and
    every subsequent triage was told "100% true-positive history" — the model
    citing itself as evidence, compounding each cycle.
    """
    if session is None or not rule_id:
        return {}

    try:
        stmt = (
            select(Alert, AlertDisposition)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.rule_id == rule_id)
            .where(AlertDisposition.analyst != AI_ANALYST)
            .order_by(Alert.created_at.desc())
            .limit(MAX_HISTORICAL_DISPOSITIONS)
        )
        result = await session.execute(stmt)
        rows = result.all()

        if not rows:
            return {}

        # Aggregate verdict counts
        verdict_counts: dict[str, int] = {}
        analyst_counts: dict[str, int] = {}
        for _alert_row, disp_row in rows:
            v = disp_row.verdict.value
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
            a = disp_row.analyst
            analyst_counts[a] = analyst_counts.get(a, 0) + 1

        total = len(rows)
        # Count both legacy "false_positive" and new "acknowledged" as the same signal
        fp_count = verdict_counts.get("false_positive", 0) + verdict_counts.get("acknowledged", 0)
        tp_count = verdict_counts.get("true_positive", 0)
        fp_rate = round(fp_count / total, 2) if total > 0 else 0

        # Recent examples (last 5)
        recent = [
            {
                "verdict": row[1].verdict.value,
                "analyst": row[1].analyst,
                "notes": (row[1].notes or "")[:100],
                "date": row[0].created_at.isoformat() if row[0].created_at else None,
            }
            for row in rows[:5]
        ]

        return {
            "total_dispositions": total,
            "verdict_breakdown": verdict_counts,
            "false_positive_rate": fp_rate,
            "true_positive_count": tp_count,
            "false_positive_count": fp_count,
            "analysts_involved": list(analyst_counts.keys())[:5],
            "recent_examples": recent,
        }
    except Exception:
        logger.warning("Failed to fetch historical dispositions", exc_info=True)
        return {}


async def _fetch_agent_history(
    agent_name: str,
    session: AsyncSession | None,
) -> dict:
    """Compute disposition stats for this specific agent/host.

    Shows whether this host tends to generate noise or real threats.
    HUMAN dispositions only — see _fetch_historical_dispositions for why
    kahu-ai's own verdicts are excluded from statistical signals.
    """
    if session is None or not agent_name:
        return {}

    try:
        stmt = (
            select(Alert, AlertDisposition)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.agent_name == agent_name)
            .where(AlertDisposition.analyst != AI_ANALYST)
            .order_by(Alert.created_at.desc())
            .limit(MAX_HISTORICAL_DISPOSITIONS)
        )
        result = await session.execute(stmt)
        rows = result.all()

        if not rows:
            return {}

        verdict_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for alert_row, disp_row in rows:
            v = disp_row.verdict.value
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
            s = (
                alert_row.severity.value
                if isinstance(alert_row.severity, Severity)
                else alert_row.severity
            )
            severity_counts[s] = severity_counts.get(s, 0) + 1

        total = len(rows)
        fp_count = verdict_counts.get("false_positive", 0) + verdict_counts.get("acknowledged", 0)
        fp_rate = round(fp_count / total, 2) if total > 0 else 0

        return {
            "agent_name": agent_name,
            "total_alerts": total,
            "verdict_breakdown": verdict_counts,
            "severity_breakdown": severity_counts,
            "false_positive_rate": fp_rate,
        }
    except Exception:
        logger.warning("Failed to fetch agent history", exc_info=True)
        return {}


def _parse_wazuh_timestamp(ts: str) -> datetime:
    """Parse Wazuh's ISO timestamp format."""
    if not ts:
        raise ValueError("Empty timestamp")
    # Wazuh uses format: 2024-01-15T10:30:00.000+0000
    ts = ts.replace("+0000", "+00:00").replace("Z", "+00:00")
    return datetime.fromisoformat(ts)
