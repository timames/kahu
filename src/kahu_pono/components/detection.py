"""Component 1: Detection posture (25 points).

Subweights:
- update_freshness: staleness threshold 7 days
- content_age: detection content age
- canary_pass_rate: fraction of canaries passing
- sensor_health: fraction of sensors reporting
- log_source_coverage: active sources vs NetBox expected
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectionInput:
    last_update_days: float = 0.0
    staleness_threshold_days: int = 7
    content_age_days: float = 0.0
    canary_total: int = 0
    canary_passed: int = 0
    sensors_total: int = 0
    sensors_healthy: int = 0
    expected_sources: int = 0
    active_sources: int = 0
    data_available: bool = True


def score_detection(inp: DetectionInput, subweights: dict[str, float]) -> tuple[float, dict]:
    """Score detection posture. Returns (raw_score 0-1, details)."""
    if not inp.data_available:
        return 0.0, {"status": "not assessed"}

    scores = {}

    # Update freshness: 1.0 if within threshold, decays linearly to 0 at 3x threshold
    if inp.last_update_days <= inp.staleness_threshold_days:
        scores["update_freshness"] = 1.0
    else:
        overage = inp.last_update_days - inp.staleness_threshold_days
        max_overage = inp.staleness_threshold_days * 2
        scores["update_freshness"] = max(0.0, 1.0 - overage / max_overage)

    # Content age: 1.0 if < 30 days, linear decay to 0 at 365 days
    scores["content_age"] = max(0.0, 1.0 - inp.content_age_days / 365.0)

    # Canary pass rate
    if inp.canary_total > 0:
        scores["canary_pass_rate"] = inp.canary_passed / inp.canary_total
    else:
        scores["canary_pass_rate"] = 1.0  # No canaries = no failures

    # Sensor health
    if inp.sensors_total > 0:
        scores["sensor_health"] = inp.sensors_healthy / inp.sensors_total
    else:
        scores["sensor_health"] = 0.0

    # Log source coverage vs NetBox expected
    if inp.expected_sources > 0:
        scores["log_source_coverage"] = min(1.0, inp.active_sources / inp.expected_sources)
    else:
        scores["log_source_coverage"] = 1.0 if inp.active_sources > 0 else 0.0

    # Weighted sum
    raw = sum(scores.get(k, 0.0) * w for k, w in subweights.items())
    return raw, scores
