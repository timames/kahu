"""Pono Score component scorers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComponentResult:
    """Result from scoring a single component."""

    name: str
    raw_score: float        # 0.0 to 1.0 (fraction of max)
    weighted_score: float   # Actual points awarded
    max_points: int         # Maximum possible points
    assessed: bool          # Whether data source is available
    label: str              # "assessed" or "not assessed"
    evidence_age_days: float = 0.0
    details: dict | None = None
