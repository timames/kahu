"""Compliance engine — coverage analysis, gap analysis, evidence freshness.

Pulls real data from the evidence store and alert history to compute which
compliance controls have active evidence, which are gaps, and what actions
would close those gaps.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert
from kahu.models.evidence import EvidenceRecord

logger = logging.getLogger(__name__)

# How old evidence can be before it's considered stale (90 days default).
EVIDENCE_FRESHNESS_DAYS = 90


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ControlStatus:
    control_id: str
    title: str
    tags: list[str]
    covered: bool
    coverage_source: str | None = None
    evidence_type: str | None = None  # "automated" | "capability" | None
    gap: bool = False
    evidence_count: int = 0
    latest_evidence: datetime | None = None
    stale: bool = False
    recommendation: str | None = None


@dataclass
class FamilyStatus:
    family_id: str
    family_name: str
    controls: list[ControlStatus]
    coverage_pct: float = 0.0
    gap_count: int = 0


@dataclass
class CoverageReport:
    framework_id: str
    framework_name: str
    total_controls: int = 0
    covered_controls: int = 0
    coverage_pct: float = 0.0
    stale_controls: int = 0
    gap_count: int = 0
    families: list[FamilyStatus] = field(default_factory=list)


@dataclass
class GapItem:
    control_id: str
    title: str
    family: str
    tags: list[str]
    priority: int  # 1 = highest
    recommendation: str


@dataclass
class GapAnalysis:
    framework_id: str
    framework_name: str
    total_gaps: int
    gaps: list[GapItem]
    quick_wins: list[GapItem]  # gaps closable by Kahu capability already present


# ---------------------------------------------------------------------------
# Kahu capability map — what Kahu can provide evidence for
# ---------------------------------------------------------------------------

KAHU_CAPABILITIES: dict[str, str] = {
    "audit_logging": (
        "Kahu continuously collects and indexes"
        " security events from all connected sources"
    ),
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
    "vulnerability_scan": "Greenbone/OpenVAS vulnerability scanning integration",
    "vulnerability_management": "Vulnerability tracking and remediation workflow",
    "patching": "Patch status monitoring via Wazuh agent inventory",
    "antimalware": "Malware detection via Wazuh rootcheck and file integrity monitoring",
    "endpoint_protection": "Wazuh agent endpoint monitoring and response",
    "configuration": "Configuration assessment via Wazuh SCA policies",
    "hardening": "CIS benchmark compliance checking via Wazuh SCA",
}

# Recommendations for tags Kahu does NOT cover — these need manual/policy controls.
MANUAL_RECOMMENDATIONS: dict[str, str] = {
    "governance": (
        "Establish a documented security governance"
        " policy and assign oversight responsibilities"
    ),
    "training": "Implement a security awareness training program for all personnel",
    "identity": "Deploy an identity provider with centralized user lifecycle management",
    "mfa": "Enable multi-factor authentication on all externally-accessible systems",
    "least_privilege": (
        "Conduct a privilege review and enforce"
        " least-privilege access across systems"
    ),
    "session_management": (
        "Configure automatic session timeout/logoff"
        " on systems handling sensitive data"
    ),
    "data_protection": "Classify data assets and implement handling procedures per classification",
    "integrity": "Implement integrity controls (checksums, digital signatures) for critical data",
    "encryption": (
        "Deploy TLS/encryption for data in transit"
        " and at rest; verify FIPS compliance if required"
    ),
    "cryptography": "Inventory cryptographic implementations and validate algorithm/key strength",
    "network_segmentation": "Segment the network to isolate publicly-accessible components",
    "boundary_protection": (
        "Deploy boundary protection (firewall, WAF)"
        " at all network trust boundaries"
    ),
    "baseline": "Establish and document baseline configurations for all system types",
    "change_management": (
        "Implement a change management process"
        " with approval, testing, and documentation"
    ),
    "risk_assessment": (
        "Conduct periodic risk assessments and"
        " document results with remediation plans"
    ),
    "security_assessment": (
        "Schedule periodic security control"
        " assessments (internal or third-party)"
    ),
    "attribution": "Ensure all system actions can be traced to individual authenticated users",
    "log_retention": "Define and enforce log retention policies meeting regulatory requirements",
    "remediation": "Establish a vulnerability remediation SLA and track closure rates",
    "testing": "Conduct periodic incident response tabletop exercises and document results",
    "netflow": "Enable network flow logging (NetFlow/sFlow) on core switches and routers",
    "asset_inventory": (
        "Maintain an up-to-date inventory of all"
        " enterprise hardware and software assets"
    ),
}


# Priority by tag category (lower = more critical for gap closure).
TAG_PRIORITY: dict[str, int] = {
    "incident_response": 1,
    "audit_logging": 1,
    "monitoring": 1,
    "access_control": 2,
    "authentication": 2,
    "vulnerability_scan": 2,
    "antimalware": 2,
    "encryption": 3,
    "configuration": 3,
    "identity": 3,
    "mfa": 3,
    "governance": 4,
    "training": 4,
    "risk_assessment": 4,
}


# ---------------------------------------------------------------------------
# Engine functions
# ---------------------------------------------------------------------------


async def compute_coverage(
    framework_id: str,
    framework: dict,
    session: AsyncSession,
) -> CoverageReport:
    """Compute full coverage report for a framework using real evidence data."""
    cutoff = datetime.now(UTC) - timedelta(days=EVIDENCE_FRESHNESS_DAYS)

    # Gather evidence stats: tag → (count, latest_timestamp)
    evidence_stats = await _evidence_stats_by_tag(session)

    # Gather alert control tags
    alert_tags = await _alert_control_tags(session)

    all_evidence_tags = set(evidence_stats.keys()) | alert_tags

    families: list[FamilyStatus] = []
    total = 0
    covered = 0
    stale = 0
    gaps = 0

    for fam_id, fam in framework["families"].items():
        controls: list[ControlStatus] = []
        for ctrl in fam["controls"]:
            total += 1
            status = _evaluate_control(ctrl, all_evidence_tags, evidence_stats, cutoff)
            if status.covered:
                covered += 1
            if status.stale:
                stale += 1
            if status.gap:
                gaps += 1
            controls.append(status)

        fam_covered = sum(1 for c in controls if c.covered)
        fam_gaps = sum(1 for c in controls if c.gap)
        families.append(
            FamilyStatus(
                family_id=fam_id,
                family_name=fam["name"],
                controls=controls,
                coverage_pct=round(fam_covered / len(controls) * 100, 1) if controls else 0,
                gap_count=fam_gaps,
            )
        )

    return CoverageReport(
        framework_id=framework_id,
        framework_name=framework["name"],
        total_controls=total,
        covered_controls=covered,
        coverage_pct=round(covered / total * 100, 1) if total else 0,
        stale_controls=stale,
        gap_count=gaps,
        families=families,
    )


async def analyze_gaps(
    framework_id: str,
    framework: dict,
    session: AsyncSession,
) -> GapAnalysis:
    """Identify uncovered controls and generate prioritised recommendations."""
    report = await compute_coverage(framework_id, framework, session)

    all_gaps: list[GapItem] = []
    quick_wins: list[GapItem] = []

    for family in report.families:
        for ctrl in family.controls:
            if not ctrl.gap:
                continue

            priority = min(
                (TAG_PRIORITY.get(tag, 5) for tag in ctrl.tags),
                default=5,
            )
            recommendation = _recommendation_for(ctrl.tags)

            item = GapItem(
                control_id=ctrl.control_id,
                title=ctrl.title,
                family=family.family_name,
                tags=ctrl.tags,
                priority=priority,
                recommendation=recommendation,
            )
            all_gaps.append(item)

            # Quick win: Kahu has the capability but no evidence yet
            has_capability = any(tag in KAHU_CAPABILITIES for tag in ctrl.tags)
            if has_capability:
                quick_wins.append(item)

    all_gaps.sort(key=lambda g: g.priority)
    quick_wins.sort(key=lambda g: g.priority)

    return GapAnalysis(
        framework_id=framework_id,
        framework_name=framework["name"],
        total_gaps=len(all_gaps),
        gaps=all_gaps,
        quick_wins=quick_wins,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _evaluate_control(
    ctrl: dict,
    all_evidence_tags: set[str],
    evidence_stats: dict[str, tuple[int, datetime | None]],
    freshness_cutoff: datetime,
) -> ControlStatus:
    """Evaluate a single control's coverage status."""
    tags: list[str] = ctrl["tags"]
    has_capability = any(tag in KAHU_CAPABILITIES for tag in tags)
    has_evidence = any(tag in all_evidence_tags for tag in tags)

    # Aggregate evidence stats across matching tags
    total_evidence = 0
    latest: datetime | None = None
    for tag in tags:
        if tag in evidence_stats:
            count, ts = evidence_stats[tag]
            total_evidence += count
            if ts and (latest is None or ts > latest):
                latest = ts

    is_stale = False
    if has_capability and has_evidence:
        coverage_source = "Kahu automated — evidence collected"
        evidence_type = "automated"
        if latest and latest < freshness_cutoff:
            is_stale = True
    elif has_capability:
        coverage_source = "Kahu capability — awaiting evidence"
        evidence_type = "capability"
    else:
        coverage_source = None
        evidence_type = None

    covered = has_capability
    gap = not covered

    recommendation = _recommendation_for(tags) if gap else None

    return ControlStatus(
        control_id=ctrl["id"],
        title=ctrl["title"],
        tags=tags,
        covered=covered,
        coverage_source=coverage_source,
        evidence_type=evidence_type,
        gap=gap,
        evidence_count=total_evidence,
        latest_evidence=latest,
        stale=is_stale,
        recommendation=recommendation,
    )


def _recommendation_for(tags: list[str]) -> str:
    """Generate a recommendation string for uncovered control tags."""
    for tag in tags:
        if tag in MANUAL_RECOMMENDATIONS:
            return MANUAL_RECOMMENDATIONS[tag]
        if tag in KAHU_CAPABILITIES:
            return f"Connect a data source to activate: {KAHU_CAPABILITIES[tag]}"
    return "Review this control and determine appropriate compensating measures"


async def _evidence_stats_by_tag(
    session: AsyncSession,
) -> dict[str, tuple[int, datetime | None]]:
    """Query evidence records and aggregate counts/timestamps per control tag.

    Evidence records store control_tags as a JSON array of strings like
    ``["800-171:3.3.1", "SOC2:CC7.1"]``. We unnest and aggregate.
    """
    from sqlalchemy import text

    dialect = session.bind.dialect.name if session.bind else "unknown"

    if dialect == "postgresql":
        sql = text("""
            SELECT tag, COUNT(*) as cnt, MAX(timestamp) as latest
            FROM evidence, jsonb_array_elements_text(control_tags) AS tag
            GROUP BY tag
        """)
        result = await session.execute(sql)
        return {row[0]: (row[1], row[2]) for row in result.all()}

    # SQLite / fallback: load records and aggregate in Python
    result = await session.execute(select(EvidenceRecord.control_tags, EvidenceRecord.timestamp))
    stats: dict[str, tuple[int, datetime | None]] = {}
    for tags, ts in result.all():
        if not tags:
            continue
        for tag in tags:
            if tag in stats:
                count, latest = stats[tag]
                stats[tag] = (count + 1, max(ts, latest) if latest else ts)
            else:
                stats[tag] = (1, ts)
    return stats


async def _alert_control_tags(session: AsyncSession) -> set[str]:
    """Collect unique control tags from all alerts."""
    result = await session.execute(select(Alert.control_tags).where(Alert.control_tags.isnot(None)))
    tags: set[str] = set()
    for row in result.scalars().all():
        if row:
            tags.update(row)
    return tags
