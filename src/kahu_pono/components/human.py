"""Component 6: Human layer (10 points).

Subweights (from weights_schema.json):
- training_completion: fraction of staff with current training
- training_recency: freshness of completed training

This is a stub component -- data sources TBD.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HumanInput:
    staff_trained: int = 0
    staff_total: int = 0
    mean_training_age_days: float = 0.0
    training_max_age_days: float = 365.0
    data_available: bool = True


def score_human(inp: HumanInput, subweights: dict[str, float]) -> tuple[float, dict]:
    """Score human layer. Returns (raw_score 0-1, details)."""
    if not inp.data_available:
        return 0.0, {"status": "not assessed"}

    scores = {}

    # Training completion
    if inp.staff_total > 0:
        scores["training_completion"] = inp.staff_trained / inp.staff_total
    else:
        scores["training_completion"] = 0.0

    # Training recency: 1.0 if fresh, linear decay to 0 at max age
    if inp.mean_training_age_days <= 0:
        scores["training_recency"] = 1.0
    else:
        scores["training_recency"] = max(
            0.0,
            1.0 - inp.mean_training_age_days / inp.training_max_age_days,
        )

    raw = sum(scores.get(k, 0.0) * w for k, w in subweights.items())
    return raw, scores
