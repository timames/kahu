"""Data models for the tuning engine state."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class WindowState:
    """Gamma posterior for a single time window."""

    alpha: float
    beta: float
    n_events: int = 0
    t_hours: float = 0.0

    @property
    def posterior_mean(self) -> float:
        if self.beta == 0:
            return 0.0
        return self.alpha / self.beta

    @property
    def posterior_variance(self) -> float:
        if self.beta == 0:
            return 0.0
        return self.alpha / (self.beta**2)

    @property
    def posterior_cv(self) -> float:
        if self.alpha <= 0:
            return float("inf")
        return 1.0 / (self.alpha**0.5)


@dataclass
class TupleState:
    """Full state for a (rule_id, source_key, asset_id) tuple."""

    rule_id: str
    source_key: str
    asset_id: str

    # Rolling window posteriors
    w_1h: WindowState = field(default_factory=lambda: WindowState(0.5, 0.5))
    w_24h: WindowState = field(default_factory=lambda: WindowState(0.5, 0.5))
    w_7d: WindowState = field(default_factory=lambda: WindowState(0.5, 0.5))
    w_90d: WindowState = field(default_factory=lambda: WindowState(0.5, 0.5))

    # Golden snapshot (never decayed)
    golden_alpha: float = 0.5
    golden_beta: float = 0.5

    last_decay_ts: datetime | None = None
    last_update_ts: datetime | None = None

    @property
    def tuple_key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.source_key, self.asset_id)

    def window(self, name: str) -> WindowState:
        return {
            "1h": self.w_1h,
            "24h": self.w_24h,
            "7d": self.w_7d,
            "90d": self.w_90d,
        }[name]


@dataclass
class SeasonalityProfile:
    """Hour-of-week multiplicative profile for a rule class."""

    rule_class: str
    # 168 hourly multipliers (Mon 00:00 = index 0)
    hourly: list[float] = field(default_factory=lambda: [1.0] * 168)
    # 3-bin fallback: business, evening, weekend
    bins: list[float] = field(default_factory=lambda: [1.0, 1.0, 1.0])
    total_events_90d: int = 0
    last_refresh: datetime | None = None

    def multiplier(self, hour_of_week: int, use_bins: bool = False) -> float:
        if use_bins:
            return self.bins[self._bin_index(hour_of_week)]
        return self.hourly[hour_of_week % 168]

    @staticmethod
    def _bin_index(hour_of_week: int) -> int:
        """0=business, 1=evening, 2=weekend."""
        day = hour_of_week // 24
        hour = hour_of_week % 24
        if day >= 5:  # Saturday (5) or Sunday (6)
            return 2
        if 7 <= hour < 18:
            return 0
        return 1


@dataclass
class FleetPrior:
    """Fleet-level Gamma prior fitted by method of moments."""

    alpha: float = 0.5
    beta: float = 0.5
    source: str = "default"  # "default" or "fleet"

    @classmethod
    def from_moments(cls, mean: float, variance: float) -> FleetPrior:
        """Fit Gamma(alpha, beta) from fleet mean and variance of per-rule rates.

        Gamma mean = alpha/beta, variance = alpha/beta^2.
        So beta = mean/variance, alpha = mean * beta.
        """
        if variance <= 0 or mean <= 0:
            return cls(alpha=0.5, beta=0.5, source="default")
        beta = mean / variance
        alpha = mean * beta
        return cls(alpha=alpha, beta=beta, source="fleet")
