"""Report data aggregation — queries for all report types."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.evidence import EvidenceRecord


async def get_alert_summary(
    session: AsyncSession,
    since: datetime,
    until: datetime | None = None,
) -> dict:
    """Aggregate alert stats for a time window."""
    until = until or datetime.now(timezone.utc)

    base = select(Alert).where(
        Alert.created_at >= since,
        Alert.created_at < until,
    )

    # Total count
    total = await session.scalar(
        select(func.count()).select_from(base.subquery())
    ) or 0

    # By severity
    sev_stmt = (
        select(Alert.severity, func.count())
        .where(Alert.created_at >= since, Alert.created_at < until)
        .group_by(Alert.severity)
    )
    sev_result = await session.execute(sev_stmt)
    by_severity = {
        (row[0].value if isinstance(row[0], Severity) else row[0]): row[1]
        for row in sev_result.all()
    }

    # Disposition breakdown
    disp_stmt = (
        select(AlertDisposition.verdict, func.count())
        .join(Alert)
        .where(Alert.created_at >= since, Alert.created_at < until)
        .group_by(AlertDisposition.verdict)
    )
    disp_result = await session.execute(disp_stmt)
    by_disposition = {
        (row[0].value if isinstance(row[0], DispositionVerdict) else row[0]): row[1]
        for row in disp_result.all()
    }

    disposed_count = sum(by_disposition.values())
    pending_count = total - disposed_count

    # Top rules
    rule_stmt = (
        select(Alert.rule_id, Alert.rule_description, func.count().label("cnt"))
        .where(Alert.created_at >= since, Alert.created_at < until)
        .group_by(Alert.rule_id, Alert.rule_description)
        .order_by(func.count().desc())
        .limit(10)
    )
    rule_result = await session.execute(rule_stmt)
    top_rules = [
        {"rule_id": r[0], "description": r[1], "count": r[2]}
        for r in rule_result.all()
    ]

    # Top source IPs (from raw_event JSON)
    # This uses a postgres JSON extraction
    ip_stmt = (
        select(
            Alert.raw_event["data"]["srcip"].astext.label("srcip"),
            func.count().label("cnt"),
        )
        .where(
            Alert.created_at >= since,
            Alert.created_at < until,
            Alert.raw_event["data"]["srcip"].astext.isnot(None),
            Alert.raw_event["data"]["srcip"].astext != "",
        )
        .group_by(Alert.raw_event["data"]["srcip"].astext)
        .order_by(func.count().desc())
        .limit(10)
    )
    try:
        ip_result = await session.execute(ip_stmt)
        top_source_ips = [
            {"ip": r[0], "count": r[1]} for r in ip_result.all()
        ]
    except Exception:
        top_source_ips = []

    # Top targeted hosts
    host_stmt = (
        select(Alert.agent_name, func.count().label("cnt"))
        .where(
            Alert.created_at >= since,
            Alert.created_at < until,
            Alert.agent_name.isnot(None),
        )
        .group_by(Alert.agent_name)
        .order_by(func.count().desc())
        .limit(10)
    )
    host_result = await session.execute(host_stmt)
    top_hosts = [
        {"host": r[0], "count": r[1]} for r in host_result.all()
    ]

    return {
        "period": {"since": since.isoformat(), "until": until.isoformat()},
        "total_alerts": total,
        "by_severity": by_severity,
        "by_disposition": by_disposition,
        "pending": pending_count,
        "disposed": disposed_count,
        "disposition_rate": round(disposed_count / total * 100, 1) if total else 0,
        "top_rules": top_rules,
        "top_source_ips": top_source_ips,
        "top_hosts": top_hosts,
    }


async def get_incident_data(
    session: AsyncSession,
    alert_ids: list[str],
) -> dict:
    """Gather all data for an incident report from a set of alert IDs."""
    import uuid

    uuids = [uuid.UUID(aid) for aid in alert_ids]

    stmt = (
        select(Alert)
        .outerjoin(AlertDisposition)
        .where(Alert.id.in_(uuids))
        .order_by(Alert.created_at.asc())
    )
    result = await session.execute(stmt)
    alerts = result.scalars().all()

    if not alerts:
        return {"error": "No alerts found for the given IDs"}

    # Build timeline
    timeline = []
    all_hosts = set()
    all_ips = set()
    severities_seen = set()

    for a in alerts:
        raw = a.raw_event or {}
        data = raw.get("data", {})
        srcip = data.get("srcip", "")
        dstip = data.get("dstip", "")

        if a.agent_name:
            all_hosts.add(a.agent_name)
        if srcip:
            all_ips.add(srcip)
        if dstip:
            all_ips.add(dstip)

        sev = a.severity.value if isinstance(a.severity, Severity) else a.severity
        severities_seen.add(sev)

        entry = {
            "timestamp": str(a.created_at),
            "severity": sev,
            "rule_id": a.rule_id,
            "rule_description": a.rule_description,
            "agent_name": a.agent_name,
            "source_ip": srcip,
            "dest_ip": dstip,
        }

        if a.llm_triage:
            entry["ai_explanation"] = a.llm_triage.get("explanation", "")

        if a.disposition:
            entry["verdict"] = a.disposition.verdict.value
            entry["analyst"] = a.disposition.analyst
            entry["disposition_notes"] = a.disposition.notes

        timeline.append(entry)

    # Determine overall severity
    sev_order = ["critical", "high", "medium", "low", "info"]
    overall_severity = "info"
    for s in sev_order:
        if s in severities_seen:
            overall_severity = s
            break

    return {
        "alert_count": len(alerts),
        "overall_severity": overall_severity,
        "time_range": {
            "first": str(alerts[0].created_at),
            "last": str(alerts[-1].created_at),
        },
        "affected_hosts": sorted(all_hosts),
        "involved_ips": sorted(all_ips),
        "timeline": timeline,
    }


async def get_evidence_summary(
    session: AsyncSession,
    since: datetime,
    until: datetime | None = None,
) -> dict:
    """Aggregate evidence records for a compliance evidence package."""
    until = until or datetime.now(timezone.utc)

    # Total records
    total = await session.scalar(
        select(func.count()).select_from(EvidenceRecord).where(
            EvidenceRecord.timestamp >= since,
            EvidenceRecord.timestamp < until,
        )
    ) or 0

    # By event type
    type_stmt = (
        select(EvidenceRecord.event_type, func.count())
        .where(
            EvidenceRecord.timestamp >= since,
            EvidenceRecord.timestamp < until,
        )
        .group_by(EvidenceRecord.event_type)
        .order_by(func.count().desc())
    )
    type_result = await session.execute(type_stmt)
    by_type = {r[0]: r[1] for r in type_result.all()}

    # Get the records themselves for the package
    records_stmt = (
        select(EvidenceRecord)
        .where(
            EvidenceRecord.timestamp >= since,
            EvidenceRecord.timestamp < until,
        )
        .order_by(EvidenceRecord.timestamp.asc())
    )
    records_result = await session.execute(records_stmt)
    records = records_result.scalars().all()

    evidence_entries = []
    chain_valid = True
    prev_hash = None

    for r in records:
        entry = {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "event_type": r.event_type,
            "control_tags": r.control_tags,
            "actor": r.actor,
            "record_hash": r.record_hash,
            "previous_hash": r.previous_hash,
        }
        # Verify chain continuity
        if prev_hash is not None and r.previous_hash != prev_hash:
            entry["chain_break"] = True
            chain_valid = False
        prev_hash = r.record_hash
        evidence_entries.append(entry)

    return {
        "period": {"since": since.isoformat(), "until": until.isoformat()},
        "total_records": total,
        "by_event_type": by_type,
        "chain_intact": chain_valid,
        "records": evidence_entries,
    }
