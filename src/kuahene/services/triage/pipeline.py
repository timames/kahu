"""Four-stage triage pipeline orchestrator.

Stage 1 — Deterministic filtering (rule-based suppression, dedup, correlation)
Stage 2 — Enrichment (asset context, related events, vuln state, history)
Stage 3 — LLM triage (structured prompt → severity, explanation, recommendations)
Stage 4 — Disposition (notification, dashboard queue, provenance logging)
"""

from dataclasses import dataclass

from kuahene.services.triage.filters import apply_deterministic_filters
from kuahene.services.triage.enrichment import enrich_alert_group
from kuahene.services.triage.llm_triage import run_llm_triage


@dataclass
class PipelineResult:
    passed_filter: bool
    enrichment: dict | None = None
    llm_output: dict | None = None
    final_severity: str | None = None
    provenance: dict | None = None


async def run_pipeline(raw_alert: dict) -> PipelineResult:
    """Process a single Wazuh alert through all four triage stages."""

    # Stage 1: Deterministic filtering
    filtered = apply_deterministic_filters(raw_alert)
    if not filtered.passed:
        return PipelineResult(passed_filter=False)

    # Stage 2: Enrichment
    enriched = await enrich_alert_group(filtered.alert)

    # Stage 3: LLM triage
    llm_result = await run_llm_triage(enriched)

    # Stage 4: Determine final severity (model advises, ruleset governs)
    final_severity = _bound_severity(
        deterministic_severity=filtered.severity,
        llm_severity=llm_result.get("severity"),
    )

    provenance = {
        "filter_rules_fired": filtered.rules_fired,
        "enrichment_sources": enriched.sources,
        "llm_input_hash": enriched.prompt_hash,
        "llm_output": llm_result,
        "final_severity": final_severity,
    }

    return PipelineResult(
        passed_filter=True,
        enrichment=enriched.data,
        llm_output=llm_result,
        final_severity=final_severity,
        provenance=provenance,
    )


def _bound_severity(deterministic_severity: str, llm_severity: str | None) -> str:
    """Model can refine severity within a band but cannot suppress critical findings."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    det_rank = severity_rank.get(deterministic_severity, 2)

    if llm_severity is None:
        return deterministic_severity

    llm_rank = severity_rank.get(llm_severity, 2)

    # LLM cannot lower severity more than one band below deterministic
    effective_rank = max(llm_rank, det_rank - 1)
    # LLM can raise severity freely
    effective_rank = max(effective_rank, det_rank) if llm_rank > det_rank else effective_rank

    rank_to_severity = {v: k for k, v in severity_rank.items()}
    return rank_to_severity.get(effective_rank, deterministic_severity)
