"""Compliance API — profiles, control mappings, coverage matrix, gap analysis.

Framework definitions (NIST 800-171, CMMC, HIPAA, CIS) are reference data.
Active profiles are persisted in PostgreSQL.
Coverage is computed from real alert evidence and active connector tags.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kuahene.db import get_session
from kuahene.models.alerts import Alert
from kuahene.models.compliance import ComplianceProfile
from kuahene.models.connectors import ConnectorInstance, ConnectorStatus

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
}

# What Kuahene capabilities map to which tags
KUAHENE_EVIDENCE_MAP = {
    "audit_logging": "Kuahene continuously collects and indexes security events from all connected sources",
    "monitoring": "Real-time monitoring via Wazuh SIEM with AI-assisted triage",
    "siem": "Wazuh SIEM/XDR integration with local AI correlation",
    "incident_response": "Automated alert triage pipeline with human-in-the-loop disposition",
    "triage": "AI-powered alert triage with severity classification and recommended actions",
    "evidence": "Append-only, hash-chained evidence store with full attribution",
    "correlation": "LLM-driven cross-alert correlation and pattern detection",
    "network_monitoring": "Network flow collection and firewall log analysis",
    "anomaly_detection": "AI-based anomaly detection on aggregated event data",
    "continuous_monitoring": "24/7 automated monitoring with degraded-mode fallback",
    "access_control": "Monitoring of authentication events and access patterns",
    "authentication": "Collection and analysis of authentication logs",
    "privilege_escalation": "Detection of privilege escalation attempts",
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
    """Get coverage matrix based on real alert evidence and active connectors."""
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail="Framework not found")

    framework = FRAMEWORKS[framework_id]

    # Gather evidence tags from real alerts
    result = await session.execute(
        select(Alert.control_tags).where(Alert.control_tags.isnot(None))
    )
    alert_tags = set()
    for row in result.scalars().all():
        if row:
            alert_tags.update(row)

    # Gather tags from active connectors
    conn_result = await session.execute(
        select(ConnectorInstance.control_tags).where(
            ConnectorInstance.status == ConnectorStatus.ACTIVE,
            ConnectorInstance.control_tags.isnot(None),
        )
    )
    connector_tags = set()
    for row in conn_result.scalars().all():
        if row:
            connector_tags.update(row)

    # Merge all evidence sources
    all_evidence_tags = alert_tags | connector_tags

    families = []
    total_controls = 0
    covered_controls = 0

    for fam_id, fam in framework["families"].items():
        controls = []
        for ctrl in fam["controls"]:
            total_controls += 1
            # A control is covered if Kuahene has the capability AND we have evidence
            has_capability = any(tag in KUAHENE_EVIDENCE_MAP for tag in ctrl["tags"])
            has_evidence = any(tag in all_evidence_tags for tag in ctrl["tags"])

            if has_capability and has_evidence:
                covered_controls += 1
                source = "Kuahene automated — evidence collected"
                evidence_type = "automated"
            elif has_capability:
                covered_controls += 1
                source = "Kuahene capability — awaiting evidence"
                evidence_type = "capability"
            else:
                source = None
                evidence_type = None

            covered = has_capability
            controls.append(ControlCoverage(
                id=ctrl["id"],
                title=ctrl["title"],
                covered=covered,
                coverage_source=source,
                evidence_type=evidence_type,
                gap=not covered,
            ))

        fam_covered = sum(1 for c in controls if c.covered)
        families.append(FamilyCoverage(
            family_id=fam_id,
            family_name=fam["name"],
            controls=controls,
            coverage_pct=round(fam_covered / len(controls) * 100, 1) if controls else 0,
        ))

    return CoverageMatrix(
        framework_id=framework_id,
        framework_name=framework["name"],
        total_controls=total_controls,
        covered_controls=covered_controls,
        coverage_pct=round(covered_controls / total_controls * 100, 1) if total_controls else 0,
        families=families,
    )


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
