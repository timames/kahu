"""Nightly batch job: update posteriors, compute BFs, emit proposals."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kahu_tuner.narration import narrate_proposal
from kahu_tuning.canary import is_canary
from kahu_tuning.config import CanaryConfig, RiskConfig, TuningConfig
from kahu_tuning.decay import apply_decay
from kahu_tuning.decision import should_suppress
from kahu_tuning.drift import check_drift
from kahu_tuning.models import FleetPrior, TupleState
from kahu_tuning.proposal import (
    add_narration,
    build_evidence_block,
    build_proposal,
    sign_proposal,
)
from kahu_tuning.seasonality import build_profile, effective_exposure
from kahu_tuning.shrinkage import hierarchical_update

log = logging.getLogger(__name__)


class BatchResult:
    """Collects outputs from a batch run."""

    def __init__(self) -> None:
        self.proposals: list[dict] = []
        self.drift_reviews: list[dict] = []
        self.canary_results: list[dict] = []
        self.tuples_processed: int = 0
        self.errors: list[str] = []


async def run_batch(
    tuple_observations: list[dict],
    states: dict[tuple[str, str, str], TupleState],
    tuning_config: TuningConfig,
    risk_config: RiskConfig,
    canary_config: CanaryConfig,
    tuning_config_raw: dict,
    risk_config_raw: dict,
    private_key: Ed25519PrivateKey,
    fleet_prior: FleetPrior | None = None,
    risk_context: dict[tuple[str, str, str], dict] | None = None,
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "qwen2.5:14b-instruct",
    today: Any = None,
) -> BatchResult:
    """Run the full nightly batch.

    Args:
        tuple_observations: Per-tuple aggregated data from OpenSearch.
            Each entry: {"rule_id", "source_key", "asset_id", "total_events",
                         "hourly_counts", "hour_of_week_indices"}
        states: Current TupleState keyed by (rule_id, source_key, asset_id).
        tuning_config: Parsed tuning configuration.
        risk_config: Parsed risk configuration.
        canary_config: Canary rule list.
        tuning_config_raw: Raw dict for config hashing.
        risk_config_raw: Raw dict for config hashing.
        private_key: Ed25519 private key for signing proposals.
        fleet_prior: Fleet-level prior (optional).
        risk_context: Per-tuple risk factors {tuple_key: {"geo_risk", "asset_criticality", ...}}.
        ollama_url: Ollama endpoint for mind narration.
        ollama_model: Model name for narration.
        today: Override date for decay (testing).
    """
    result = BatchResult()
    risk_ctx = risk_context or {}

    for obs in tuple_observations:
        rule_id = obs["rule_id"]
        source_key = obs["source_key"]
        asset_id = obs["asset_id"]
        key = (rule_id, source_key, asset_id)

        # Skip canary rules
        if is_canary(rule_id, canary_config):
            result.canary_results.append(
                {
                    "rule_id": rule_id,
                    "status": "canary_excluded",
                }
            )
            continue

        try:
            state = states.get(
                key,
                TupleState(
                    rule_id=rule_id,
                    source_key=source_key,
                    asset_id=asset_id,
                ),
            )

            # Build seasonality profile from 90d hour-of-week data
            event_hours = obs.get("hour_of_week_indices", [])
            profile = build_profile(rule_id, event_hours, tuning_config)

            # Compute effective exposure
            observation_hours = obs.get("hour_of_week_indices", [])
            n_total = obs.get("total_events", 0)
            t_star = effective_exposure(observation_hours, profile, tuning_config)
            if t_star <= 0:
                t_star = max(len(observation_hours), 1)

            # Build per-window observations
            # For batch, we use 90d as the primary window
            observations = {
                "90d": (n_total, t_star),
                "7d": (0, 0.0),
                "24h": (0, 0.0),
                "1h": (0, 0.0),
            }

            # Hierarchical update
            state = hierarchical_update(state, observations, tuning_config, fleet_prior)

            # Apply decay
            state = apply_decay(state, today=today, config=tuning_config)

            # Update stored state
            state.last_update_ts = datetime.now(UTC)
            states[key] = state

            # Drift check
            drift, kl = check_drift(
                state.w_90d.alpha,
                state.w_90d.beta,
                state.golden_alpha,
                state.golden_beta,
                epsilon=tuning_config.kl_epsilon_default,
            )

            if drift:
                result.drift_reviews.append(
                    {
                        "tuple": {
                            "rule_id": rule_id,
                            "source_key": source_key,
                            "asset_id": asset_id,
                        },
                        "kl_divergence": round(kl, 6),
                        "mean_90d": round(state.w_90d.posterior_mean, 6),
                        "mean_golden": round(
                            state.golden_alpha / state.golden_beta if state.golden_beta > 0 else 0,
                            6,
                        ),
                        "detected_at": datetime.now(UTC).isoformat(),
                    }
                )
                # Drift tuples NEVER get suppression proposals
                result.tuples_processed += 1
                continue

            # Risk multiplier
            from kahu_tuning.risk import compute_risk_multiplier

            ctx = risk_ctx.get(key, {})
            r = compute_risk_multiplier(
                geo_risk=ctx.get("geo_risk", "low"),
                asset_criticality=ctx.get("asset_criticality", "standard"),
                misp_overlap=ctx.get("misp_overlap", False),
                protocol_class=ctx.get("protocol_class", ""),
                config=risk_config,
            )

            # Decision
            suppress, po, log_bf, threshold = should_suppress(
                n=n_total,
                alpha0=state.w_90d.alpha,
                beta0=state.w_90d.beta,
                t_star=t_star,
                risk_multiplier=r,
                config=tuning_config,
            )

            # Check window consistency (all windows agree on benign)
            windows_consistent = _check_windows_consistent(state)

            if suppress and windows_consistent:
                evidence = build_evidence_block(
                    n_90d=n_total,
                    t_star_hours=t_star,
                    posterior_mean=state.w_90d.posterior_mean,
                    posterior_cv=state.w_90d.posterior_cv,
                    log_bf01=log_bf,
                    posterior_odds=po,
                    risk_multiplier=r,
                    threshold_applied=threshold,
                    kl_vs_golden=kl,
                    windows_consistent=windows_consistent,
                )

                proposal = build_proposal(
                    rule_id=rule_id,
                    source_key=source_key,
                    asset_id=asset_id,
                    action="demote",
                    action_params={"target_level": max(1, int(state.w_90d.posterior_mean))},
                    evidence=evidence,
                    tuning_config_raw=tuning_config_raw,
                    risk_config_raw=risk_config_raw,
                )

                # Sign BEFORE narration
                proposal = sign_proposal(proposal, private_key)

                # Mind narration (strictly out of decision path)
                try:
                    narration = await narrate_proposal(
                        evidence,
                        ollama_url=ollama_url,
                        model=ollama_model,
                    )
                    if narration:
                        proposal = add_narration(proposal, narration)
                except Exception:  # noqa: S110
                    pass  # noqa: S110

                result.proposals.append(proposal)

            result.tuples_processed += 1

        except Exception as e:
            log.exception("Error processing tuple %s", key)
            result.errors.append(f"{key}: {e}")

    return result


def _check_windows_consistent(state: TupleState) -> bool:
    """Check that all windows agree the rate is stable (no short-term spikes)."""
    means = []
    for w_name in ("1h", "24h", "7d", "90d"):
        w = state.window(w_name)
        if w.beta > 0 and w.alpha > 0:
            means.append(w.posterior_mean)

    if len(means) < 2:
        return True

    # Windows are consistent if no window mean is more than 3x any other
    min_mean = min(means)
    max_mean = max(means)
    if min_mean <= 0:
        return True
    return max_mean / min_mean < 3.0
