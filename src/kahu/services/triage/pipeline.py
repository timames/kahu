"""Four-stage triage pipeline orchestrator.

Stage 1 — Deterministic filtering (rule-based suppression, dedup, correlation)
Stage 2 — Enrichment (asset context, related events, vuln state, history)
Stage 3 — LLM triage (structured prompt -> severity, explanation, recommendations)
Stage 4 — Disposition (persistence, evidence recording, notifications)

The severity displayed to the customer is min/max-bounded by deterministic rules.
The model can refine severity within a band but cannot suppress a critical
deterministic finding. The model advises; the ruleset governs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.ollama import OllamaClient
from kahu.clients.wazuh import WazuhIndexerClient
from kahu.models.alerts import MutedRule
from kahu.services.triage.auto_disposition import maybe_auto_dispose
from kahu.services.triage.disposition import persist_alert
from kahu.services.triage.enrichment import enrich_alert_group
from kahu.services.triage.filters import FilterResult, apply_deterministic_filters
from kahu.services.triage.llm_triage import run_llm_triage

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


@dataclass
class PipelineResult:
    passed_filter: bool
    filter_result: FilterResult | None = None
    enrichment: dict | None = None
    llm_output: dict | None = None
    final_severity: str | None = None
    provenance: dict | None = None
    alert_id: str | None = None
    degraded: bool = False
    muted: bool = False


@dataclass
class PipelineStats:
    """Counters for a batch run — useful for health reporting."""

    total: int = 0
    filtered: int = 0
    muted: int = 0
    triaged: int = 0
    persisted: int = 0
    auto_disposed: int = 0
    errors: int = 0


async def get_active_muted_rule_ids(session: AsyncSession) -> set[str]:
    """Rule IDs with an active, unexpired user mute. Fetched once per batch."""
    now = datetime.now(UTC)
    stmt = select(MutedRule.rule_id).where(
        MutedRule.active == True,  # noqa: E712 — SQLAlchemy expression, not identity
        or_(MutedRule.expires_at.is_(None), MutedRule.expires_at > now),
    )
    return set((await session.execute(stmt)).scalars().all())


async def run_pipeline(
    raw_alert: dict,
    session: AsyncSession | None = None,
    indexer: WazuhIndexerClient | None = None,
    ollama: OllamaClient | None = None,
    muted_rules: set[str] | None = None,
) -> PipelineResult:
    """Process a single Wazuh alert through all four triage stages."""

    # Stage 1: Deterministic filtering
    filtered = apply_deterministic_filters(raw_alert)
    if not filtered.passed:
        return PipelineResult(
            passed_filter=False,
            filter_result=filtered,
        )

    # User rule mute: persist a minimal row (audit trail intact) but skip
    # enrichment, LLM triage, and auto-disposition, and hide from the queue.
    # Guardrail — the governing invariant applies here too: a mute can NEVER
    # silence a CRITICAL_RULE_IDS hit or a deterministically high/critical
    # alert. Both checks read the raw deterministic FilterResult, so nothing
    # the model (or an attacker-controlled log body) says can widen a mute.
    rule_id = str(raw_alert.get("rule", {}).get("id", ""))
    if (
        muted_rules
        and rule_id in muted_rules
        and not filtered.critical_rule
        and filtered.severity not in ("high", "critical")
    ):
        result = PipelineResult(
            passed_filter=True,
            filter_result=filtered,
            final_severity=filtered.severity,
            provenance={
                "muted_by_rule": rule_id,
                "stages": ["filters", "muted"],
                "deterministic_severity": filtered.severity,
                "final_severity": filtered.severity,
            },
            muted=True,
        )
        if session is not None:
            try:
                alert = await persist_alert(result, raw_alert, session)
                result.alert_id = str(alert.id)
            except Exception:
                logger.error("Failed to persist muted alert", exc_info=True)
        return result

    # Stage 2: Enrichment
    enriched = await enrich_alert_group(
        filtered.alert,
        session=session,
        indexer=indexer,
    )

    # Stage 3: LLM triage
    llm_result = await run_llm_triage(enriched, ollama=ollama)
    degraded = llm_result.get("degraded", False)

    # Bound severity: model advises, ruleset governs
    final_severity = _bound_severity(
        deterministic_severity=filtered.severity,
        llm_severity=llm_result.get("severity"),
    )

    provenance = {
        "filter_rules_fired": filtered.rules_fired,
        "correlation_key": filtered.correlation_key,
        "enrichment_sources": enriched.sources,
        "llm_input_hash": enriched.prompt_hash,
        "llm_output": llm_result,
        "deterministic_severity": filtered.severity,
        "llm_severity": llm_result.get("severity"),
        "final_severity": final_severity,
        "degraded": degraded,
    }

    result = PipelineResult(
        passed_filter=True,
        filter_result=filtered,
        enrichment=enriched.data,
        llm_output=llm_result,
        final_severity=final_severity,
        provenance=provenance,
        degraded=degraded,
    )

    # Stage 4: Persist to DB and record evidence
    if session is not None:
        try:
            alert = await persist_alert(result, raw_alert, session)
            result.alert_id = str(alert.id)

            # Stage 5: Auto-disposition (AI handles obvious cases).
            # Pass the DETERMINISTIC severity and critical-rule flag so the
            # ruleset keeps governing the auto-dismiss decision, not just the
            # displayed severity number.
            auto_result = await maybe_auto_dispose(
                alert,
                llm_result,
                session,
                deterministic_severity=filtered.severity,
                critical_rule=filtered.critical_rule,
            )
            if auto_result.auto_handled:
                result.provenance["auto_disposed"] = True
                result.provenance["auto_verdict"] = auto_result.verdict
                result.provenance["auto_confidence"] = auto_result.confidence
            if auto_result.floor_blocked_dismiss:
                # A model-driven dismissal was refused by the deterministic
                # floor. Record it: this is a security-relevant event.
                result.provenance["auto_dismiss_blocked_by_floor"] = True
        except Exception:
            logger.error("Failed to persist alert", exc_info=True)

    return result


async def run_pipeline_batch(
    raw_alerts: list[dict],
    session: AsyncSession | None = None,
    indexer: WazuhIndexerClient | None = None,
    ollama: OllamaClient | None = None,
) -> tuple[list[PipelineResult], PipelineStats]:
    """Process a batch of Wazuh alerts. Returns results and stats."""
    stats = PipelineStats(total=len(raw_alerts))
    results: list[PipelineResult] = []

    muted_rules: set[str] = set()
    if session is not None:
        try:
            muted_rules = await get_active_muted_rule_ids(session)
        except Exception:
            logger.warning("Failed to load muted rules — proceeding unmuted", exc_info=True)

    for raw_alert in raw_alerts:
        try:
            result = await run_pipeline(
                raw_alert,
                session=session,
                indexer=indexer,
                ollama=ollama,
                muted_rules=muted_rules,
            )
            results.append(result)

            if not result.passed_filter:
                stats.filtered += 1
            elif result.muted:
                stats.muted += 1
                if result.alert_id:
                    stats.persisted += 1
            else:
                stats.triaged += 1
                if result.alert_id:
                    stats.persisted += 1
                if result.provenance and result.provenance.get("auto_disposed"):
                    stats.auto_disposed += 1
        except Exception:
            stats.errors += 1
            logger.error("Pipeline error for alert", exc_info=True)

    return results, stats


def _bound_severity(deterministic_severity: str, llm_severity: str | None) -> str:
    """Model can refine severity within a band but cannot suppress critical findings.

    Rules:
    - LLM cannot lower severity more than one band below deterministic
    - LLM can raise severity freely
    - If LLM returns None, deterministic severity stands
    """
    det_rank = SEVERITY_RANK.get(deterministic_severity, 2)

    if llm_severity is None:
        return deterministic_severity

    llm_rank = SEVERITY_RANK.get(llm_severity, 2)

    # LLM cannot lower more than one band
    floor = max(0, det_rank - 1)
    effective_rank = max(llm_rank, floor)

    return RANK_TO_SEVERITY.get(effective_rank, deterministic_severity)
