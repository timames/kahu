"""Exponential freshness decay on evidence age."""

from __future__ import annotations

import math
from datetime import datetime, timezone


def freshness_factor(
    evidence_age_days: float,
    delta: float = 0.992,
) -> float:
    """Compute exponential freshness decay factor.

    factor = delta ^ age_days

    At delta=0.992:
    - 1 day old: 0.992
    - 7 days: 0.945
    - 30 days: 0.787
    - 90 days: 0.486
    - 120 days: 0.383

    Returns value in [0, 1]. Older evidence contributes less.
    """
    if evidence_age_days <= 0:
        return 1.0
    return delta ** evidence_age_days


def evidence_age_days(
    evidence_timestamp: datetime | str | None,
    now: datetime | None = None,
) -> float:
    """Compute age of evidence in fractional days."""
    if evidence_timestamp is None:
        return float("inf")
    if now is None:
        now = datetime.now(timezone.utc)
    if isinstance(evidence_timestamp, str):
        evidence_timestamp = datetime.fromisoformat(evidence_timestamp)
    if evidence_timestamp.tzinfo is None:
        evidence_timestamp = evidence_timestamp.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delta = now - evidence_timestamp
    return max(0.0, delta.total_seconds() / 86400.0)


def apply_freshness(
    raw_score: float,
    evidence_age: float,
    delta: float = 0.992,
) -> float:
    """Apply freshness decay to a raw component score."""
    return raw_score * freshness_factor(evidence_age, delta)
