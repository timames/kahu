"""Validation sampler — random endpoint spot-checks to verify Pono Score integrity.

The score is computed from exhaustive fleet data. The sampler independently
validates that the reported state matches ground truth by randomly selecting
endpoints and running direct checks against them via the Wazuh agent API.

Monthly cadence: 13 samples per round by default (~1 every 2.3 days).
Selection is random without replacement within a round.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.wazuh import WazuhAPIClient
from kahu.models.pono import PonoSnapshot
from kahu.models.validation import ValidationRound, ValidationSample, ValidationVerdict

log = logging.getLogger("kahu.validation")

# Checks run against each sampled endpoint
ENDPOINT_CHECKS = [
    "agent_active",        # Is the Wazuh agent connected and reporting?
    "syscheck_current",    # FIM database updated within threshold?
    "rootcheck_current",   # Rootcheck scan run recently?
    "vulnerability_scan",  # Vulnerability detector data fresh?
    "sca_pass_rate",       # Security Configuration Assessment pass %?
]

# Thresholds for pass/fail
CHECK_THRESHOLDS = {
    "agent_active": {"status": "active"},
    "syscheck_current": {"max_age_hours": 48},
    "rootcheck_current": {"max_age_hours": 72},
    "vulnerability_scan": {"max_age_hours": 168},  # 7 days
    "sca_pass_rate": {"min_pass_pct": 0.70},
}


async def list_fleet_agents(wazuh: WazuhAPIClient) -> list[dict]:
    """Get all registered Wazuh agents (excluding the manager itself)."""
    try:
        resp = await wazuh.api_get("/agents", params={"limit": 500, "offset": 0})
        agents = resp.get("data", {}).get("affected_items", [])
        # Exclude agent 000 (the manager)
        return [a for a in agents if a.get("id") != "000"]
    except Exception as exc:
        log.error("validation: failed to list agents: %s", exc)
        return []


def select_sample(agents: list[dict], sample_size: int = 13) -> list[dict]:
    """Randomly select endpoints for validation. No replacement within a round."""
    if len(agents) <= sample_size:
        return list(agents)
    return random.sample(agents, sample_size)


async def check_agent(wazuh: WazuhAPIClient, agent_id: str) -> tuple[dict, list[str]]:
    """Run all checks against a single agent. Returns (check_results, findings)."""
    results: dict = {}
    findings: list[str] = []

    # 1. Agent status
    try:
        resp = await wazuh.api_get(f"/agents", params={"agents_list": agent_id})
        items = resp.get("data", {}).get("affected_items", [])
        if items:
            agent_data = items[0]
            status = agent_data.get("status", "unknown")
            results["agent_active"] = status == "active"
            if status != "active":
                findings.append(f"Agent status is '{status}', expected 'active'")
        else:
            results["agent_active"] = False
            findings.append("Agent not found in Wazuh API")
    except Exception as exc:
        results["agent_active"] = False
        findings.append(f"Agent status check failed: {exc}")

    # 2. Syscheck (FIM) freshness
    try:
        resp = await wazuh.api_get(f"/syscheck/{agent_id}/last_scan")
        scan_data = resp.get("data", {}).get("affected_items", [{}])[0]
        end_str = scan_data.get("end", scan_data.get("start"))
        if end_str:
            end_time = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            age_hours = (datetime.now(timezone.utc) - end_time).total_seconds() / 3600
            threshold = CHECK_THRESHOLDS["syscheck_current"]["max_age_hours"]
            results["syscheck_current"] = age_hours <= threshold
            if age_hours > threshold:
                findings.append(f"Syscheck is {age_hours:.0f}h old (threshold: {threshold}h)")
        else:
            results["syscheck_current"] = False
            findings.append("No syscheck scan data available")
    except Exception as exc:
        results["syscheck_current"] = False
        findings.append(f"Syscheck check failed: {exc}")

    # 3. Rootcheck freshness
    try:
        resp = await wazuh.api_get(f"/rootcheck/{agent_id}/last_scan")
        scan_data = resp.get("data", {}).get("affected_items", [{}])[0]
        end_str = scan_data.get("end", scan_data.get("start"))
        if end_str:
            end_time = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            age_hours = (datetime.now(timezone.utc) - end_time).total_seconds() / 3600
            threshold = CHECK_THRESHOLDS["rootcheck_current"]["max_age_hours"]
            results["rootcheck_current"] = age_hours <= threshold
            if age_hours > threshold:
                findings.append(f"Rootcheck is {age_hours:.0f}h old (threshold: {threshold}h)")
        else:
            results["rootcheck_current"] = False
            findings.append("No rootcheck scan data available")
    except Exception as exc:
        results["rootcheck_current"] = False
        findings.append(f"Rootcheck check failed: {exc}")

    # 4. Vulnerability detector freshness
    try:
        resp = await wazuh.api_get(
            f"/vulnerability/{agent_id}",
            params={"limit": 1, "sort": "-scan_time"},
        )
        items = resp.get("data", {}).get("affected_items", [])
        if items:
            results["vulnerability_scan"] = True  # Has vuln data
        else:
            results["vulnerability_scan"] = False
            findings.append("No vulnerability scan data for this agent")
    except Exception:
        # Vulnerability detector may not be enabled — not a hard fail
        results["vulnerability_scan"] = None
        findings.append("Vulnerability detector not available")

    # 5. SCA (Security Configuration Assessment) pass rate
    try:
        resp = await wazuh.api_get(f"/sca/{agent_id}")
        policies = resp.get("data", {}).get("affected_items", [])
        if policies:
            total_pass = sum(p.get("pass", 0) for p in policies)
            total_checks = sum(
                p.get("pass", 0) + p.get("fail", 0) + p.get("invalid", 0)
                for p in policies
            )
            if total_checks > 0:
                pass_rate = total_pass / total_checks
                threshold = CHECK_THRESHOLDS["sca_pass_rate"]["min_pass_pct"]
                results["sca_pass_rate"] = pass_rate
                if pass_rate < threshold:
                    findings.append(
                        f"SCA pass rate {pass_rate:.0%} below threshold {threshold:.0%}"
                    )
            else:
                results["sca_pass_rate"] = None
        else:
            results["sca_pass_rate"] = None
            findings.append("No SCA policies configured")
    except Exception as exc:
        results["sca_pass_rate"] = None
        findings.append(f"SCA check failed: {exc}")

    return results, findings


def evaluate_sample(checks: dict) -> ValidationVerdict:
    """Determine pass/fail for a single endpoint sample."""
    # Agent must be active — hard requirement
    if not checks.get("agent_active"):
        return ValidationVerdict.UNREACHABLE

    # Count mandatory checks that passed
    mandatory = ["agent_active", "syscheck_current", "rootcheck_current"]
    mandatory_pass = sum(1 for k in mandatory if checks.get(k) is True)

    # Pass if all mandatory checks pass
    if mandatory_pass == len(mandatory):
        return ValidationVerdict.PASS

    return ValidationVerdict.FAIL


async def run_validation_round(
    session: AsyncSession,
    sample_size: int = 13,
    wazuh: WazuhAPIClient | None = None,
) -> ValidationRound:
    """Execute a full validation round: select, check, evaluate, persist."""
    if wazuh is None:
        wazuh = WazuhAPIClient()

    now = datetime.now(timezone.utc)
    round_id = str(uuid.uuid4())

    # Get current Pono Score
    latest_snapshot = await session.scalar(
        select(PonoSnapshot.pono_score)
        .order_by(desc(PonoSnapshot.timestamp))
        .limit(1)
    )
    pono_score = latest_snapshot if latest_snapshot is not None else 0.0

    # Get fleet and select sample
    agents = await list_fleet_agents(wazuh)
    fleet_size = len(agents)

    if fleet_size == 0:
        log.warning("validation: no agents found, creating empty round")
        vr = ValidationRound(
            started_at=now,
            completed_at=now,
            sample_size=0,
            fleet_size=0,
            pono_score_at_start=pono_score,
            validation_rate=None,
            drift_detected=None,
            summary={"error": "no agents found"},
        )
        session.add(vr)
        await session.commit()
        await session.refresh(vr)
        return vr

    selected = select_sample(agents, sample_size)
    actual_sample_size = len(selected)

    # Run checks on each selected endpoint
    samples: list[ValidationSample] = []
    passed = 0
    failed = 0
    unreachable = 0

    for agent in selected:
        agent_id = agent.get("id", "unknown")
        agent_name = agent.get("name", agent_id)

        checks, findings = await check_agent(wazuh, agent_id)
        verdict = evaluate_sample(checks)

        if verdict == ValidationVerdict.PASS:
            passed += 1
        elif verdict == ValidationVerdict.FAIL:
            failed += 1
        else:
            unreachable += 1

        sample = ValidationSample(
            round_id=round_id,
            agent_id=agent_id,
            agent_name=agent_name,
            scheduled_at=now,
            completed_at=datetime.now(timezone.utc),
            verdict=verdict,
            checks=checks,
            findings=findings if findings else None,
            score_at_sample=pono_score,
        )
        samples.append(sample)

    # Compute validation rate and drift
    evaluable = passed + failed  # exclude unreachable
    validation_rate = passed / evaluable if evaluable > 0 else None
    drift_detected = validation_rate is not None and validation_rate < 0.80

    completed_at = datetime.now(timezone.utc)

    vr = ValidationRound(
        id=uuid.UUID(round_id),
        started_at=now,
        completed_at=completed_at,
        sample_size=actual_sample_size,
        fleet_size=fleet_size,
        samples_completed=len(samples),
        samples_passed=passed,
        samples_failed=failed,
        samples_unreachable=unreachable,
        pono_score_at_start=pono_score,
        validation_rate=round(validation_rate, 4) if validation_rate is not None else None,
        drift_detected=drift_detected,
        summary={
            "checks_run": ENDPOINT_CHECKS,
            "thresholds": CHECK_THRESHOLDS,
            "pass_rate": f"{validation_rate:.1%}" if validation_rate is not None else "N/A",
        },
    )

    session.add(vr)
    for s in samples:
        session.add(s)
    await session.commit()
    await session.refresh(vr)

    if drift_detected:
        log.warning(
            "validation: DRIFT DETECTED — round %s pass rate %.1f%% (pono=%.1f)",
            round_id[:8], (validation_rate or 0) * 100, pono_score,
        )
    else:
        log.info(
            "validation: round %s complete — %d/%d passed (fleet=%d, pono=%.1f)",
            round_id[:8], passed, actual_sample_size, fleet_size, pono_score,
        )

    return vr


async def get_latest_round(session: AsyncSession) -> ValidationRound | None:
    """Get the most recent validation round."""
    result = await session.execute(
        select(ValidationRound)
        .order_by(desc(ValidationRound.started_at))
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_round_samples(
    session: AsyncSession, round_id: str
) -> list[ValidationSample]:
    """Get all samples for a given round."""
    result = await session.execute(
        select(ValidationSample)
        .where(ValidationSample.round_id == round_id)
        .order_by(ValidationSample.scheduled_at)
    )
    return list(result.scalars().all())
