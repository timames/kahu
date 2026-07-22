"""Component 2: Tuning hygiene (15 points).

Subweights (from weights_schema.json):
- active_suppression_count: normalized active suppressions
- mean_tune_age: freshness of tuning rules
- expired_unreviewed: fraction of proposals not expired/unreviewed
- drift_flags_unacked: fraction of drift flags acknowledged
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TuningInput:
    active_suppressions: int = 0
    expected_suppressions: int = 0
    mean_tune_age_days: float = 0.0
    tune_age_threshold_days: float = 90.0
    total_proposals: int = 0
    expired_unreviewed: int = 0
    drift_flags_total: int = 0
    drift_flags_unacked: int = 0
    data_available: bool = True


def score_tuning(inp: TuningInput, subweights: dict[str, float]) -> tuple[float, dict]:
    """Score tuning hygiene. Returns (raw_score 0-1, details)."""
    if not inp.data_available:
        return 0.0, {"status": "not assessed"}

    scores = {}

    # Active suppression count: ratio of active vs expected
    if inp.expected_suppressions > 0:
        scores["active_suppression_count"] = min(1.0, inp.active_suppressions / inp.expected_suppressions)
    else:
        scores["active_suppression_count"] = 1.0 if inp.active_suppressions > 0 else 0.0

    # Mean tune age: 1.0 if fresh, linear decay to 0 at 3x threshold
    if inp.mean_tune_age_days <= inp.tune_age_threshold_days:
        scores["mean_tune_age"] = 1.0
    else:
        overage = inp.mean_tune_age_days - inp.tune_age_threshold_days
        max_overage = inp.tune_age_threshold_days * 2
        scores["mean_tune_age"] = max(0.0, 1.0 - overage / max_overage)

    # Expired unreviewed: 1.0 if none expired
    if inp.total_proposals > 0:
        scores["expired_unreviewed"] = 1.0 - (inp.expired_unreviewed / inp.total_proposals)
    else:
        scores["expired_unreviewed"] = 1.0

    # Drift flags unacked: 1.0 if all acknowledged
    if inp.drift_flags_total > 0:
        scores["drift_flags_unacked"] = 1.0 - (inp.drift_flags_unacked / inp.drift_flags_total)
    else:
        scores["drift_flags_unacked"] = 1.0

    raw = sum(scores.get(k, 0.0) * w for k, w in subweights.items())
    return raw, scores
