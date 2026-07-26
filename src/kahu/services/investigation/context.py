"""Investigation context gathering — pulls relevant data from Postgres and Wazuh indexer."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.wazuh import WazuhIndexerClient
from kahu.models.alerts import Alert, AlertDisposition, Severity

log = logging.getLogger("kahu.investigation.context")

# Patterns for extracting structured hints from natural-language questions
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:host|server|agent|machine)\s+(\S+)", re.IGNORECASE)
_RULE_RE = re.compile(r"\brule\s*(?:id\s*)?(\d+)\b", re.IGNORECASE)
_TIME_RE = re.compile(
    r"\b(?:last|past)\s+(\d+)\s*(hour|hours|day|days|minute|minutes|min|mins|hr|hrs)\b",
    re.IGNORECASE,
)
_NAMED_TIME_RE = re.compile(r"\b(today|yesterday|this week)\b", re.IGNORECASE)


def parse_question(question: str) -> dict:
    """Extract structured filters from a natural-language question."""
    hints: dict = {}

    # IPs
    ips = _IP_RE.findall(question)
    if ips:
        hints["ips"] = ips

    # Hostnames
    hosts = _HOST_RE.findall(question)
    if hosts:
        hints["hosts"] = [h.strip(".,;:?!") for h in hosts]

    # Rule IDs
    rules = _RULE_RE.findall(question)
    if rules:
        hints["rule_ids"] = rules

    # Severity
    q_lower = question.lower()
    for sev in ("critical", "high", "medium", "low"):
        if sev in q_lower:
            hints["severity"] = sev
            break

    # Time range
    time_match = _TIME_RE.search(question)
    if time_match:
        amount = int(time_match.group(1))
        unit = time_match.group(2).lower().rstrip("s")
        if unit in ("hr", "hour"):
            hints["since"] = datetime.now(timezone.utc) - timedelta(hours=amount)
        elif unit in ("day",):
            hints["since"] = datetime.now(timezone.utc) - timedelta(days=amount)
        elif unit in ("min", "minute"):
            hints["since"] = datetime.now(timezone.utc) - timedelta(minutes=amount)

    named_match = _NAMED_TIME_RE.search(question)
    if named_match and "since" not in hints:
        word = named_match.group(1).lower()
        now = datetime.now(timezone.utc)
        if word == "today":
            hints["since"] = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif word == "yesterday":
            hints["since"] = (now - timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            hints["until"] = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif word == "this week":
            hints["since"] = now - timedelta(days=now.weekday())

    return hints


async def gather_from_postgres(
    session: AsyncSession,
    hints: dict,
    limit: int = 50,
) -> list[dict]:
    """Query local alert database with parsed filters."""
    stmt = select(Alert).outerjoin(AlertDisposition)

    # Apply filters
    if "severity" in hints:
        sev_map = {
            "critical": [Severity.CRITICAL],
            "high": [Severity.CRITICAL, Severity.HIGH],
            "medium": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
            "low": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        }
        stmt = stmt.where(Alert.severity.in_(sev_map.get(hints["severity"], [])))

    if "since" in hints:
        stmt = stmt.where(Alert.created_at >= hints["since"])

    if "until" in hints:
        stmt = stmt.where(Alert.created_at < hints["until"])

    if "hosts" in hints:
        from sqlalchemy import or_

        host_filters = [Alert.agent_name.ilike(f"%{h}%") for h in hints["hosts"]]
        stmt = stmt.where(or_(*host_filters))

    if "rule_ids" in hints:
        stmt = stmt.where(Alert.rule_id.in_(hints["rule_ids"]))

    # IP filtering requires checking raw_event JSON
    if "ips" in hints:
        from sqlalchemy import or_, cast, String

        ip_filters = []
        for ip in hints["ips"]:
            ip_filters.append(
                cast(Alert.raw_event, String).contains(ip)
            )
        stmt = stmt.where(or_(*ip_filters))

    # If no filters matched, default to undispositioned alerts
    if not hints:
        stmt = stmt.where(AlertDisposition.id.is_(None))

    stmt = stmt.order_by(Alert.created_at.desc()).limit(limit)

    result = await session.execute(stmt)
    alerts = result.scalars().all()

    return [_alert_to_dict(a) for a in alerts]


async def gather_from_indexer(
    hints: dict,
    limit: int = 30,
) -> list[dict]:
    """Query Wazuh indexer (OpenSearch) for raw log data."""
    indexer = WazuhIndexerClient()

    must_clauses: list[dict] = []

    # Time range
    time_range: dict = {}
    if "since" in hints:
        time_range["gte"] = hints["since"].isoformat()
    if "until" in hints:
        time_range["lt"] = hints["until"].isoformat()
    if not time_range:
        time_range["gte"] = "now-24h"
    must_clauses.append({"range": {"timestamp": time_range}})

    # IP filter — search across source and destination
    if "ips" in hints:
        ip_shoulds = []
        for ip in hints["ips"]:
            ip_shoulds.extend([
                {"match": {"data.srcip": ip}},
                {"match": {"data.dstip": ip}},
                {"match_phrase": {"full_log": ip}},
            ])
        must_clauses.append({"bool": {"should": ip_shoulds, "minimum_should_match": 1}})

    # Host/agent filter
    if "hosts" in hints:
        host_shoulds = [{"wildcard": {"agent.name": f"*{h}*"}} for h in hints["hosts"]]
        must_clauses.append({"bool": {"should": host_shoulds, "minimum_should_match": 1}})

    # Rule ID filter
    if "rule_ids" in hints:
        must_clauses.append({"terms": {"rule.id": hints["rule_ids"]}})

    # Severity filter
    if "severity" in hints:
        sev = hints["severity"]
        level_ranges = {
            "critical": {"gte": 12},
            "high": {"gte": 10},
            "medium": {"gte": 7},
            "low": {"gte": 4},
        }
        if sev in level_ranges:
            must_clauses.append({"range": {"rule.level": level_ranges[sev]}})

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must_clauses}},
    }

    try:
        resp = await indexer.search("wazuh-alerts-*", query)
        hits = resp.get("hits", {}).get("hits", [])
        return [_indexer_hit_to_dict(h) for h in hits]
    except Exception as e:
        log.warning("Indexer query failed: %s", e)
        return []


def _alert_to_dict(a: Alert) -> dict:
    """Convert a Postgres Alert to a context dict."""
    llm = a.llm_triage or {}
    raw = a.raw_event or {}
    return {
        "source": "postgres",
        "severity": a.severity.value if isinstance(a.severity, Severity) else a.severity,
        "rule_id": a.rule_id,
        "rule_description": a.rule_description,
        "agent_name": a.agent_name,
        "created_at": str(a.created_at),
        "ai_explanation": llm.get("explanation", ""),
        "source_ip": raw.get("data", {}).get("srcip", ""),
        "dest_ip": raw.get("data", {}).get("dstip", ""),
        "disposed": a.disposition is not None,
        "verdict": a.disposition.verdict.value if a.disposition else None,
    }


def _indexer_hit_to_dict(hit: dict) -> dict:
    """Convert a Wazuh indexer hit to a context dict."""
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})
    return {
        "source": "wazuh_indexer",
        "timestamp": src.get("timestamp", ""),
        "rule_id": rule.get("id", ""),
        "rule_description": rule.get("description", ""),
        "rule_level": rule.get("level", 0),
        "agent_name": agent.get("name", ""),
        "source_ip": data.get("srcip", ""),
        "dest_ip": data.get("dstip", ""),
        "full_log": src.get("full_log", "")[:500],
    }
