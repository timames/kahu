"""Compliance API — profiles, control mappings, coverage matrix, gap analysis.

Framework definitions (NIST 800-171, CMMC, HIPAA, CIS) are reference data.
Active profiles are persisted in PostgreSQL.
Coverage is computed from real alert evidence and active connector tags.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, desc, func as sa_func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.models.compliance import ComplianceProfile
from kahu.models.evidence import EvidenceRecord
from kahu.services.compliance.engine import analyze_gaps, compute_coverage
from kahu.services.compliance.evidence import verify_chain

router = APIRouter()

# ---------------------------------------------------------------------------
# Compliance frameworks (reference data — these are real control catalogs)
# ---------------------------------------------------------------------------

FRAMEWORKS = {
    "nist_800_171": {
        "name": "NIST 800-171 Rev 2",
        "description": "Protecting Controlled Unclassified Information (CUI) in Nonfederal Systems",
        "version": "Rev 2",
        "families": {
            "3.1": {"name": "Access Control", "controls": [
                {"id": "3.1.1", "title": "Limit system access to authorized users", "tags": ["access_control", "authentication"]},
                {"id": "3.1.2", "title": "Limit system access to authorized functions", "tags": ["access_control", "authorization"]},
                {"id": "3.1.5", "title": "Employ the principle of least privilege", "tags": ["least_privilege", "access_control"]},
                {"id": "3.1.7", "title": "Prevent non-privileged users from executing privileged functions", "tags": ["privilege_escalation"]},
            ]},
            "3.3": {"name": "Audit and Accountability", "controls": [
                {"id": "3.3.1", "title": "Create and retain system audit logs", "tags": ["audit_logging", "log_retention"]},
                {"id": "3.3.2", "title": "Ensure actions can be traced to individual users", "tags": ["audit_logging", "attribution"]},
                {"id": "3.3.4", "title": "Alert on audit logging process failures", "tags": ["audit_logging", "monitoring"]},
                {"id": "3.3.5", "title": "Correlate audit review, analysis, and reporting", "tags": ["audit_logging", "correlation"]},
            ]},
            "3.4": {"name": "Configuration Management", "controls": [
                {"id": "3.4.1", "title": "Establish and maintain baseline configurations", "tags": ["configuration", "baseline"]},
                {"id": "3.4.2", "title": "Establish and enforce security configuration settings", "tags": ["configuration", "hardening"]},
                {"id": "3.4.5", "title": "Define and enforce physical and logical access restrictions", "tags": ["access_control", "configuration"]},
            ]},
            "3.5": {"name": "Identification and Authentication", "controls": [
                {"id": "3.5.1", "title": "Identify system users and processes", "tags": ["authentication", "identity"]},
                {"id": "3.5.2", "title": "Authenticate users and processes", "tags": ["authentication", "mfa"]},
                {"id": "3.5.3", "title": "Use multifactor authentication for network access", "tags": ["mfa", "authentication"]},
            ]},
            "3.6": {"name": "Incident Response", "controls": [
                {"id": "3.6.1", "title": "Establish an operational incident-handling capability", "tags": ["incident_response", "triage"]},
                {"id": "3.6.2", "title": "Track, document, and report incidents", "tags": ["incident_response", "evidence"]},
                {"id": "3.6.3", "title": "Test the incident response capability", "tags": ["incident_response", "testing"]},
            ]},
            "3.11": {"name": "Risk Assessment", "controls": [
                {"id": "3.11.1", "title": "Periodically assess risk to operations and assets", "tags": ["risk_assessment"]},
                {"id": "3.11.2", "title": "Scan for vulnerabilities periodically", "tags": ["vulnerability_scan", "risk_assessment"]},
                {"id": "3.11.3", "title": "Remediate vulnerabilities in accordance with risk", "tags": ["vulnerability_management", "remediation"]},
            ]},
            "3.12": {"name": "Security Assessment", "controls": [
                {"id": "3.12.1", "title": "Periodically assess security controls", "tags": ["security_assessment"]},
                {"id": "3.12.3", "title": "Monitor security controls on an ongoing basis", "tags": ["continuous_monitoring"]},
            ]},
            "3.13": {"name": "System and Communications Protection", "controls": [
                {"id": "3.13.1", "title": "Monitor, control, and protect communications at boundaries", "tags": ["network_monitoring", "boundary_protection"]},
                {"id": "3.13.5", "title": "Implement subnetworks for publicly accessible system components", "tags": ["network_segmentation"]},
                {"id": "3.13.11", "title": "Employ FIPS-validated cryptography", "tags": ["encryption", "cryptography"]},
            ]},
            "3.14": {"name": "System and Information Integrity", "controls": [
                {"id": "3.14.1", "title": "Identify, report, and correct system flaws in a timely manner", "tags": ["patching", "vulnerability_management"]},
                {"id": "3.14.2", "title": "Provide protection from malicious code", "tags": ["antimalware", "endpoint_protection"]},
                {"id": "3.14.6", "title": "Monitor organizational systems", "tags": ["monitoring", "siem"]},
                {"id": "3.14.7", "title": "Identify unauthorized use of organizational systems", "tags": ["anomaly_detection", "monitoring"]},
            ]},
        },
    },
    "cmmc_l2": {
        "name": "CMMC Level 2",
        "description": "Cybersecurity Maturity Model Certification — Advanced (aligns with NIST 800-171)",
        "version": "2.0",
        "families": {
            "AC": {"name": "Access Control", "controls": [
                {"id": "AC.L2-3.1.1", "title": "Authorized Access Control", "tags": ["access_control"]},
                {"id": "AC.L2-3.1.2", "title": "Transaction & Function Control", "tags": ["access_control", "authorization"]},
                {"id": "AC.L2-3.1.5", "title": "Least Privilege", "tags": ["least_privilege"]},
            ]},
            "AU": {"name": "Audit & Accountability", "controls": [
                {"id": "AU.L2-3.3.1", "title": "System Auditing", "tags": ["audit_logging"]},
                {"id": "AU.L2-3.3.2", "title": "User Accountability", "tags": ["audit_logging", "attribution"]},
            ]},
            "IR": {"name": "Incident Response", "controls": [
                {"id": "IR.L2-3.6.1", "title": "Incident Handling", "tags": ["incident_response", "triage"]},
                {"id": "IR.L2-3.6.2", "title": "Incident Reporting", "tags": ["incident_response", "evidence"]},
            ]},
            "SI": {"name": "System & Information Integrity", "controls": [
                {"id": "SI.L2-3.14.1", "title": "Flaw Remediation", "tags": ["patching"]},
                {"id": "SI.L2-3.14.2", "title": "Malicious Code Protection", "tags": ["antimalware"]},
                {"id": "SI.L2-3.14.6", "title": "Security Alerts & Advisories", "tags": ["monitoring", "siem"]},
            ]},
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act — Technical Safeguards",
        "version": "2013",
        "families": {
            "164.312(a)": {"name": "Access Control", "controls": [
                {"id": "164.312(a)(1)", "title": "Implement access controls for ePHI", "tags": ["access_control"]},
                {"id": "164.312(a)(2)(i)", "title": "Assign unique user identification", "tags": ["identity", "authentication"]},
                {"id": "164.312(a)(2)(iii)", "title": "Automatic logoff", "tags": ["session_management"]},
            ]},
            "164.312(b)": {"name": "Audit Controls", "controls": [
                {"id": "164.312(b)", "title": "Implement audit controls to record and examine activity", "tags": ["audit_logging", "monitoring"]},
            ]},
            "164.312(c)": {"name": "Integrity", "controls": [
                {"id": "164.312(c)(1)", "title": "Protect ePHI from improper alteration or destruction", "tags": ["integrity", "data_protection"]},
            ]},
            "164.312(d)": {"name": "Authentication", "controls": [
                {"id": "164.312(d)", "title": "Verify identity of persons seeking access to ePHI", "tags": ["authentication", "mfa"]},
            ]},
            "164.312(e)": {"name": "Transmission Security", "controls": [
                {"id": "164.312(e)(1)", "title": "Guard against unauthorized access during transmission", "tags": ["encryption", "network_monitoring"]},
                {"id": "164.312(e)(2)(ii)", "title": "Implement encryption for ePHI in transit", "tags": ["encryption"]},
            ]},
        },
    },
    "cis_controls_v8": {
        "name": "CIS Controls v8",
        "description": "Center for Internet Security — Critical Security Controls",
        "version": "8.0",
        "families": {
            "CIS-1": {"name": "Inventory and Control of Enterprise Assets", "controls": [
                {"id": "CIS-1.1", "title": "Establish and maintain enterprise asset inventory", "tags": ["asset_inventory"]},
            ]},
            "CIS-4": {"name": "Secure Configuration", "controls": [
                {"id": "CIS-4.1", "title": "Establish and maintain secure configuration process", "tags": ["configuration", "hardening"]},
            ]},
            "CIS-6": {"name": "Access Control Management", "controls": [
                {"id": "CIS-6.1", "title": "Establish access granting process", "tags": ["access_control"]},
                {"id": "CIS-6.3", "title": "Require MFA for externally-exposed applications", "tags": ["mfa"]},
            ]},
            "CIS-8": {"name": "Audit Log Management", "controls": [
                {"id": "CIS-8.1", "title": "Establish and maintain audit log management process", "tags": ["audit_logging"]},
                {"id": "CIS-8.2", "title": "Collect audit logs", "tags": ["audit_logging", "siem"]},
                {"id": "CIS-8.5", "title": "Collect detailed audit logs", "tags": ["audit_logging", "monitoring"]},
            ]},
            "CIS-10": {"name": "Malware Defenses", "controls": [
                {"id": "CIS-10.1", "title": "Deploy and maintain anti-malware software", "tags": ["antimalware", "endpoint_protection"]},
            ]},
            "CIS-13": {"name": "Network Monitoring and Defense", "controls": [
                {"id": "CIS-13.1", "title": "Centralize security event alerting", "tags": ["siem", "monitoring"]},
                {"id": "CIS-13.6", "title": "Collect network traffic flow logs", "tags": ["network_monitoring", "netflow"]},
            ]},
            "CIS-17": {"name": "Incident Response Management", "controls": [
                {"id": "CIS-17.1", "title": "Designate personnel to manage incident handling", "tags": ["incident_response"]},
                {"id": "CIS-17.4", "title": "Establish and maintain an incident response process", "tags": ["incident_response", "triage"]},
            ]},
        },
    },
    "soc2_type2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2 — Trust Services Criteria",
        "version": "2017 (2022 update)",
        "families": {
            "CC1": {"name": "Control Environment", "controls": [
                {"id": "CC1.1", "title": "COSO Principle 1: Integrity and ethical values", "tags": ["governance"]},
                {"id": "CC1.2", "title": "COSO Principle 2: Board oversight", "tags": ["governance"]},
                {"id": "CC1.3", "title": "COSO Principle 3: Management structure and authority", "tags": ["governance"]},
                {"id": "CC1.4", "title": "COSO Principle 4: Competence commitment", "tags": ["governance", "training"]},
                {"id": "CC1.5", "title": "COSO Principle 5: Accountability", "tags": ["governance", "attribution"]},
            ]},
            "CC2": {"name": "Communication and Information", "controls": [
                {"id": "CC2.1", "title": "Internally generated information for system controls", "tags": ["audit_logging", "monitoring"]},
                {"id": "CC2.2", "title": "Internal communication of control objectives", "tags": ["governance"]},
                {"id": "CC2.3", "title": "External communication of matters affecting controls", "tags": ["incident_response", "evidence"]},
            ]},
            "CC3": {"name": "Risk Assessment", "controls": [
                {"id": "CC3.1", "title": "Identification of objectives and risk tolerance", "tags": ["risk_assessment"]},
                {"id": "CC3.2", "title": "Risk identification and analysis", "tags": ["risk_assessment", "vulnerability_scan"]},
                {"id": "CC3.3", "title": "Consider potential for fraud", "tags": ["anomaly_detection", "risk_assessment"]},
                {"id": "CC3.4", "title": "Identification and assessment of changes", "tags": ["configuration", "monitoring"]},
            ]},
            "CC4": {"name": "Monitoring Activities", "controls": [
                {"id": "CC4.1", "title": "Ongoing and/or separate evaluations of controls", "tags": ["continuous_monitoring", "security_assessment"]},
                {"id": "CC4.2", "title": "Communicate control deficiencies timely", "tags": ["incident_response", "monitoring"]},
            ]},
            "CC5": {"name": "Control Activities", "controls": [
                {"id": "CC5.1", "title": "Selection and development of control activities", "tags": ["configuration", "hardening"]},
                {"id": "CC5.2", "title": "Technology general controls selection", "tags": ["access_control", "configuration"]},
                {"id": "CC5.3", "title": "Deployment of control activities through policies", "tags": ["governance", "configuration"]},
            ]},
            "CC6": {"name": "Logical and Physical Access Controls", "controls": [
                {"id": "CC6.1", "title": "Logical access security software, infrastructure, architectures", "tags": ["access_control", "authentication"]},
                {"id": "CC6.2", "title": "User registration and authorization", "tags": ["identity", "access_control"]},
                {"id": "CC6.3", "title": "Role-based access and least privilege", "tags": ["least_privilege", "access_control"]},
                {"id": "CC6.6", "title": "System boundary security measures", "tags": ["network_monitoring", "boundary_protection"]},
                {"id": "CC6.7", "title": "Restrict data movement to authorized users", "tags": ["data_protection", "access_control"]},
                {"id": "CC6.8", "title": "Prevent or detect unauthorized or malicious software", "tags": ["antimalware", "endpoint_protection"]},
            ]},
            "CC7": {"name": "System Operations", "controls": [
                {"id": "CC7.1", "title": "Detection and monitoring of infrastructure and software", "tags": ["monitoring", "siem"]},
                {"id": "CC7.2", "title": "Monitor system components for anomalies", "tags": ["anomaly_detection", "monitoring"]},
                {"id": "CC7.3", "title": "Evaluate security events for incidents", "tags": ["triage", "incident_response"]},
                {"id": "CC7.4", "title": "Respond to identified security incidents", "tags": ["incident_response", "evidence"]},
                {"id": "CC7.5", "title": "Identify and communicate containment/remediation activities", "tags": ["incident_response", "remediation"]},
            ]},
            "CC8": {"name": "Change Management", "controls": [
                {"id": "CC8.1", "title": "Authorize, design, develop, configure, document, test, approve changes", "tags": ["configuration", "change_management"]},
            ]},
            "CC9": {"name": "Risk Mitigation", "controls": [
                {"id": "CC9.1", "title": "Identify and assess risk mitigation activities", "tags": ["risk_assessment", "vulnerability_management"]},
                {"id": "CC9.2", "title": "Assess and manage risks from vendors and partners", "tags": ["risk_assessment"]},
            ]},
            "A1": {"name": "Availability", "controls": [
                {"id": "A1.1", "title": "Maintain, monitor, and evaluate processing capacity", "tags": ["monitoring", "continuous_monitoring"]},
                {"id": "A1.2", "title": "Provide recovery of infrastructure and data", "tags": ["incident_response"]},
            ]},
            "C1": {"name": "Confidentiality", "controls": [
                {"id": "C1.1", "title": "Identify and maintain confidential information", "tags": ["data_protection", "access_control"]},
                {"id": "C1.2", "title": "Dispose of confidential information", "tags": ["data_protection"]},
            ]},
        },
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProfileActivateIn(BaseModel):
    framework_id: str
    organization_name: str = Field(..., min_length=1)
    scope: str = Field(default="All systems")


class ControlCoverage(BaseModel):
    id: str
    title: str
    covered: bool
    coverage_source: str | None = None
    evidence_type: str | None = None
    gap: bool = False
    evidence_count: int = 0
    stale: bool = False


class FamilyCoverage(BaseModel):
    family_id: str
    family_name: str
    controls: list[ControlCoverage]
    coverage_pct: float


class CoverageMatrix(BaseModel):
    framework_id: str
    framework_name: str
    total_controls: int
    covered_controls: int
    coverage_pct: float
    families: list[FamilyCoverage]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/frameworks")
async def list_frameworks() -> dict:
    """List all available compliance frameworks."""
    return {
        "frameworks": [
            {
                "id": fid,
                "name": f["name"],
                "description": f["description"],
                "version": f["version"],
                "control_count": sum(len(fam["controls"]) for fam in f["families"].values()),
            }
            for fid, f in FRAMEWORKS.items()
        ]
    }


@router.get("/frameworks/{framework_id}")
async def get_framework(framework_id: str) -> dict:
    """Get full detail of a compliance framework including all controls."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {"framework": FRAMEWORKS[framework_id], "id": framework_id}


@router.get("/frameworks/{framework_id}/coverage")
async def get_coverage(
    framework_id: str,
    session: AsyncSession = Depends(get_session),
) -> CoverageMatrix:
    """Get coverage matrix with evidence freshness and gap indicators."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    report = await compute_coverage(framework_id, FRAMEWORKS[framework_id], session)

    families = []
    for fam in report.families:
        controls = [
            ControlCoverage(
                id=c.control_id,
                title=c.title,
                covered=c.covered,
                coverage_source=c.coverage_source,
                evidence_type=c.evidence_type,
                gap=c.gap,
                evidence_count=c.evidence_count,
                stale=c.stale,
            )
            for c in fam.controls
        ]
        families.append(FamilyCoverage(
            family_id=fam.family_id,
            family_name=fam.family_name,
            controls=controls,
            coverage_pct=fam.coverage_pct,
        ))

    return CoverageMatrix(
        framework_id=report.framework_id,
        framework_name=report.framework_name,
        total_controls=report.total_controls,
        covered_controls=report.covered_controls,
        coverage_pct=report.coverage_pct,
        families=families,
    )


@router.get("/frameworks/{framework_id}/gaps")
async def get_gaps(
    framework_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Gap analysis — uncovered controls with prioritised recommendations."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    analysis = await analyze_gaps(framework_id, FRAMEWORKS[framework_id], session)

    return {
        "framework_id": analysis.framework_id,
        "framework_name": analysis.framework_name,
        "total_gaps": analysis.total_gaps,
        "gaps": [
            {
                "control_id": g.control_id,
                "title": g.title,
                "family": g.family,
                "priority": g.priority,
                "recommendation": g.recommendation,
            }
            for g in analysis.gaps
        ],
        "quick_wins": [
            {
                "control_id": g.control_id,
                "title": g.title,
                "family": g.family,
                "priority": g.priority,
                "recommendation": g.recommendation,
            }
            for g in analysis.quick_wins
        ],
    }


@router.get("/profiles")
async def list_profiles(session: AsyncSession = Depends(get_session)) -> dict:
    """List active compliance profiles (from DB)."""
    result = await session.execute(
        select(ComplianceProfile).order_by(ComplianceProfile.created_at.desc())
    )
    profiles = result.scalars().all()
    return {
        "profiles": [
            {
                "framework_id": p.framework_id,
                "framework_name": p.framework_name,
                "organization_name": p.organization_name,
                "scope": p.scope,
                "status": p.status,
                "control_count": p.control_count,
                "created_at": p.created_at.isoformat(),
            }
            for p in profiles
        ]
    }


@router.post("/profiles")
async def activate_profile(
    body: ProfileActivateIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Activate a compliance framework profile (persisted in DB)."""
    if body.framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unknown framework")

    # Check if already active
    existing = await session.scalar(
        select(ComplianceProfile).where(
            ComplianceProfile.framework_id == body.framework_id
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="Framework already active")

    fw = FRAMEWORKS[body.framework_id]
    profile = ComplianceProfile(
        framework_id=body.framework_id,
        framework_name=fw["name"],
        organization_name=body.organization_name,
        scope=body.scope,
        status="active",
        control_count=sum(len(fam["controls"]) for fam in fw["families"].values()),
    )
    session.add(profile)
    await session.commit()
    await session.refresh(profile)

    return {
        "framework_id": profile.framework_id,
        "framework_name": profile.framework_name,
        "organization_name": profile.organization_name,
        "scope": profile.scope,
        "status": profile.status,
        "control_count": profile.control_count,
        "created_at": profile.created_at.isoformat(),
    }


@router.delete("/profiles/{framework_id}", status_code=204)
async def deactivate_profile(
    framework_id: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Deactivate a compliance profile (removes from DB)."""
    result = await session.execute(
        select(ComplianceProfile).where(
            ComplianceProfile.framework_id == framework_id
        )
    )
    profile = result.scalar_one_or_none()
    if profile:
        await session.delete(profile)
        await session.commit()


@router.get("/evidence")
async def get_evidence(
    framework_id: str | None = Query(None),
    control_id: str | None = Query(None),
    event_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Query the evidence store, optionally filtering by framework control tags or event type."""
    stmt = select(EvidenceRecord).order_by(desc(EvidenceRecord.timestamp))

    if event_type:
        stmt = stmt.where(EvidenceRecord.event_type == event_type)

    # If a specific control_id is given, filter for records containing that control tag
    if control_id:
        # Match evidence records whose control_tags array contains a tag starting with the control id
        # Evidence tags use format like "800-171:3.3.1", "HIPAA:164.312(b)", "CIS:8.2"
        stmt = stmt.where(EvidenceRecord.control_tags.cast(String).contains(control_id))
    elif framework_id:
        # Get all control IDs for this framework and match any
        if framework_id in FRAMEWORKS:
            fw = FRAMEWORKS[framework_id]
            all_tags = set()
            for fam in fw["families"].values():
                for ctrl in fam["controls"]:
                    all_tags.update(ctrl["tags"])
            # Filter evidence that has any of these capability tags
            tag_filters = [
                EvidenceRecord.control_tags.cast(String).contains(tag)
                for tag in all_tags
            ]
            if tag_filters:
                stmt = stmt.where(or_(*tag_filters))

    count_stmt = select(sa_func.count()).select_from(stmt.subquery())
    total = await session.scalar(count_stmt) or 0

    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    records = result.scalars().all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "records": [
            {
                "id": str(r.id),
                "timestamp": r.timestamp.isoformat(),
                "event_type": r.event_type,
                "control_tags": r.control_tags,
                "payload": r.payload,
                "actor": r.actor,
                "record_hash": r.record_hash[:12],
            }
            for r in records
        ],
    }


@router.get("/evidence/summary")
async def evidence_summary(
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Summary stats for the evidence store — total records, by type, chain integrity."""
    total = await session.scalar(select(sa_func.count(EvidenceRecord.id))) or 0

    # Count by event_type
    type_stmt = (
        select(EvidenceRecord.event_type, sa_func.count())
        .group_by(EvidenceRecord.event_type)
    )
    type_result = await session.execute(type_stmt)
    by_type = {row[0]: row[1] for row in type_result.all()}

    # Latest record
    latest = await session.scalar(
        select(EvidenceRecord.timestamp)
        .order_by(desc(EvidenceRecord.timestamp))
        .limit(1)
    )

    chain_intact, broken_at = await verify_chain(session)

    return {
        "total_records": total,
        "by_type": by_type,
        "latest_timestamp": latest.isoformat() if latest else None,
        "chain_intact": chain_intact,
        **({"broken_at": broken_at} if broken_at else {}),
    }
