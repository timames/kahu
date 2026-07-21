"""Vulnerability scanning API — real scans backed by Wazuh + PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.wazuh import WazuhIndexerClient
from kahu.db import get_session
from kahu.models.vulnerabilities import (
    FindingStatus,
    ScanStatus,
    VulnFinding,
    VulnScan,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    scan_type: str = Field(..., pattern="^(full|network|host_config|cve_check)$")
    targets: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Wazuh scan engine (real data only)
# ---------------------------------------------------------------------------

async def _run_vuln_scan(
    scan_id: uuid.UUID,
    scan_type: str,
    targets: list[str],
    session: AsyncSession,
) -> int:
    """Pull vulnerability data from Wazuh indexer, deduplicate, and persist."""
    indexer = WazuhIndexerClient()
    count = 0

    # Pull vulnerability-detector alerts
    if scan_type in ("full", "cve_check"):
        try:
            query: dict = {
                "size": 500,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [
                    {"term": {"rule.groups": "vulnerability-detector"}}
                ]}},
            }
            if targets:
                query["query"]["bool"]["must"].append(
                    {"terms": {"agent.name": targets}}
                )
            result = await indexer.search(index="wazuh-alerts-*", query=query)
            hits = result.get("hits", {}).get("hits", [])

            for hit in hits:
                src = hit["_source"]
                vuln = src.get("data", {}).get("vulnerability", {})
                cve_id = vuln.get("cve")
                host = src.get("agent", {}).get("name", "unknown")
                source_ref = f"wazuh:{hit['_id']}"

                # Deduplicate: skip if same CVE+host already open
                if cve_id:
                    existing = await session.scalar(
                        select(func.count()).select_from(VulnFinding).where(
                            VulnFinding.cve_id == cve_id,
                            VulnFinding.affected_host == host,
                            VulnFinding.status == FindingStatus.OPEN,
                        )
                    )
                    if existing and existing > 0:
                        continue

                finding = VulnFinding(
                    scan_id=scan_id,
                    severity=_map_cvss_to_severity(
                        vuln.get("cvss", {}).get("cvss3", {}).get("base_score", 0)
                    ),
                    category="cve",
                    title=vuln.get("title", src.get("rule", {}).get("description", "Unknown vulnerability")),
                    description=vuln.get("rationale", "Detected by Wazuh vulnerability detector"),
                    affected_host=host,
                    cve_id=cve_id,
                    cvss_score=vuln.get("cvss", {}).get("cvss3", {}).get("base_score"),
                    remediation=vuln.get("remediation", "Update affected package to latest version"),
                    source="wazuh_vuln",
                    source_ref=source_ref,
                )
                session.add(finding)
                count += 1
        except Exception:
            pass

    # Pull SCA (Security Configuration Assessment) results
    if scan_type in ("full", "host_config"):
        try:
            query = {
                "size": 500,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [
                    {"term": {"rule.groups": "sca"}}
                ]}},
            }
            if targets:
                query["query"]["bool"]["must"].append(
                    {"terms": {"agent.name": targets}}
                )
            result = await indexer.search(index="wazuh-alerts-*", query=query)
            hits = result.get("hits", {}).get("hits", [])

            for hit in hits:
                src = hit["_source"]
                sca = src.get("data", {}).get("sca", {})
                if sca.get("check", {}).get("result") != "failed":
                    continue

                check_title = sca.get("check", {}).get("title", "Configuration check failed")
                host = src.get("agent", {}).get("name", "unknown")
                source_ref = f"wazuh:{hit['_id']}"

                # Deduplicate by title+host
                existing = await session.scalar(
                    select(func.count()).select_from(VulnFinding).where(
                        VulnFinding.title == check_title,
                        VulnFinding.affected_host == host,
                        VulnFinding.status == FindingStatus.OPEN,
                    )
                )
                if existing and existing > 0:
                    continue

                finding = VulnFinding(
                    scan_id=scan_id,
                    severity="medium",
                    category="misconfiguration",
                    title=check_title,
                    description=sca.get("check", {}).get("description", ""),
                    affected_host=host,
                    remediation=sca.get("check", {}).get("remediation", "Apply recommended configuration"),
                    source="wazuh_sca",
                    source_ref=source_ref,
                )
                session.add(finding)
                count += 1
        except Exception:
            pass

    # Pull rootcheck / system audit results
    if scan_type in ("full", "network"):
        try:
            query = {
                "size": 200,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"should": [
                    {"term": {"rule.groups": "rootcheck"}},
                    {"term": {"rule.groups": "syscheck"}},
                ], "minimum_should_match": 1}},
            }
            if targets:
                query["query"]["bool"]["must"] = [
                    {"terms": {"agent.name": targets}}
                ]
            result = await indexer.search(index="wazuh-alerts-*", query=query)
            hits = result.get("hits", {}).get("hits", [])

            for hit in hits:
                src = hit["_source"]
                rule_desc = src.get("rule", {}).get("description", "System integrity check")
                host = src.get("agent", {}).get("name", "unknown")
                rule_level = src.get("rule", {}).get("level", 5)
                source_ref = f"wazuh:{hit['_id']}"

                existing = await session.scalar(
                    select(func.count()).select_from(VulnFinding).where(
                        VulnFinding.title == rule_desc,
                        VulnFinding.affected_host == host,
                        VulnFinding.status == FindingStatus.OPEN,
                    )
                )
                if existing and existing > 0:
                    continue

                severity = "high" if rule_level >= 12 else "medium" if rule_level >= 7 else "low"
                finding = VulnFinding(
                    scan_id=scan_id,
                    severity=severity,
                    category="integrity",
                    title=rule_desc,
                    description=f"Wazuh rule level {rule_level} — {src.get('rule', {}).get('description', '')}",
                    affected_host=host,
                    source="wazuh_integrity",
                    source_ref=source_ref,
                )
                session.add(finding)
                count += 1
        except Exception:
            pass

    if count > 0:
        await session.flush()
    return count


def _map_cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/scans")
async def list_scans(session: AsyncSession = Depends(get_session)) -> dict:
    """List all vulnerability scans."""
    result = await session.execute(
        select(VulnScan).order_by(VulnScan.created_at.desc()).limit(50)
    )
    scans = result.scalars().all()
    return {
        "scans": [
            {
                "id": str(s.id),
                "scan_type": s.scan_type,
                "targets": s.targets,
                "status": s.status.value,
                "started_at": s.created_at.isoformat(),
                "completed_at": s.updated_at.isoformat() if s.status == ScanStatus.COMPLETED else None,
                "finding_count": s.finding_count,
                "error": s.error,
            }
            for s in scans
        ],
        "total": len(scans),
    }


@router.post("/scans")
async def start_scan(
    body: ScanRequest,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Start a new vulnerability scan."""
    scan = VulnScan(
        scan_type=body.scan_type,
        targets=body.targets,
        status=ScanStatus.RUNNING,
    )
    session.add(scan)
    await session.flush()

    try:
        count = await _run_vuln_scan(scan.id, body.scan_type, body.targets, session)
        scan.status = ScanStatus.COMPLETED
        scan.finding_count = count
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error = str(e)

    await session.commit()
    await session.refresh(scan)

    return {
        "id": str(scan.id),
        "scan_type": scan.scan_type,
        "targets": scan.targets,
        "status": scan.status.value,
        "started_at": scan.created_at.isoformat(),
        "completed_at": scan.updated_at.isoformat() if scan.status == ScanStatus.COMPLETED else None,
        "finding_count": scan.finding_count,
        "error": scan.error,
    }


@router.get("/findings")
async def list_findings(
    severity: str | None = None,
    status: str | None = None,
    host: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List vulnerability findings with optional filters."""
    stmt = select(VulnFinding)

    if severity:
        stmt = stmt.where(VulnFinding.severity == severity)
    if status:
        stmt = stmt.where(VulnFinding.status == FindingStatus(status))
    if host:
        stmt = stmt.where(VulnFinding.affected_host == host)

    sev_order = case(
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        value=VulnFinding.severity,
        else_=5,
    )
    stmt = stmt.order_by(sev_order, VulnFinding.created_at.desc())

    result = await session.execute(stmt)
    findings = result.scalars().all()

    rows = [
        {
            "id": str(f.id),
            "scan_id": str(f.scan_id),
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "affected_host": f.affected_host,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "remediation": f.remediation,
            "status": f.status.value,
            "source": f.source,
            "detected_at": f.created_at.isoformat(),
        }
        for f in findings
    ]

    stats = {
        "total": len(rows),
        "critical": sum(1 for r in rows if r["severity"] == "critical"),
        "high": sum(1 for r in rows if r["severity"] == "high"),
        "medium": sum(1 for r in rows if r["severity"] == "medium"),
        "low": sum(1 for r in rows if r["severity"] == "low"),
        "open": sum(1 for r in rows if r["status"] == "open"),
        "resolved": sum(1 for r in rows if r["status"] == "resolved"),
    }

    return {"findings": rows, "stats": stats}


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: uuid.UUID,
    status: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Update a finding's status."""
    finding = await session.get(VulnFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus(status)
    await session.commit()
    await session.refresh(finding)

    return {
        "id": str(finding.id),
        "status": finding.status.value,
        "title": finding.title,
        "affected_host": finding.affected_host,
    }


@router.get("/summary")
async def vulnerability_summary(session: AsyncSession = Depends(get_session)) -> dict:
    """Get overall vulnerability posture summary."""
    open_q = select(VulnFinding).where(VulnFinding.status == FindingStatus.OPEN)
    result = await session.execute(open_q)
    open_findings = result.scalars().all()

    hosts = set(f.affected_host for f in open_findings)

    last_scan_result = await session.execute(
        select(VulnScan).order_by(VulnScan.created_at.desc()).limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()

    total_scans = await session.scalar(select(func.count()).select_from(VulnScan)) or 0

    return {
        "total_findings": len(open_findings),
        "critical": sum(1 for f in open_findings if f.severity == "critical"),
        "high": sum(1 for f in open_findings if f.severity == "high"),
        "medium": sum(1 for f in open_findings if f.severity == "medium"),
        "low": sum(1 for f in open_findings if f.severity == "low"),
        "affected_hosts": len(hosts),
        "last_scan": last_scan.updated_at.isoformat() if last_scan else None,
        "scan_count": total_scans,
    }
