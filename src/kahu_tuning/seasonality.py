"""Seasonality estimation and effective exposure computation."""

from __future__ import annotations

from kahu_tuning.config import TuningConfig
from kahu_tuning.models import SeasonalityProfile


def estimate_hourly_profile(
    event_hours: list[int],
) -> list[float]:
    """Estimate hour-of-week multipliers from observed event timestamps.

    Args:
        event_hours: List of hour-of-week indices (0..167) for events in the 90d window.

    Returns:
        168-element list of multiplicative factors, normalized to mean 1.
    """
    counts = [0] * 168
    for h in event_hours:
        counts[h % 168] += 1

    total = sum(counts)
    if total == 0:
        return [1.0] * 168

    mean_count = total / 168.0
    return [c / mean_count if mean_count > 0 else 1.0 for c in counts]


def estimate_bin_profile(
    event_hours: list[int],
    config: TuningConfig | None = None,
) -> list[float]:
    """Estimate 3-bin profile: business, evening, weekend.

    Used when fewer than seasonality_min_events events in 90d.
    """
    cfg = config or TuningConfig()
    biz_start, biz_end = cfg.seasonality_business_hours
    biz_days = set(cfg.seasonality_business_days)

    bins = [0, 0, 0]  # business, evening, weekend
    bin_hours = [0, 0, 0]

    # Count hours in each bin for normalization
    for h in range(168):
        idx = _bin_index(h, biz_start, biz_end, biz_days)
        bin_hours[idx] += 1

    for h in event_hours:
        idx = _bin_index(h % 168, biz_start, biz_end, biz_days)
        bins[idx] += 1

    total = sum(bins)
    if total == 0:
        return [1.0, 1.0, 1.0]

    # Normalize: rate per hour in each bin, then scale to mean 1 overall
    rates = []
    for i in range(3):
        if bin_hours[i] == 0:
            rates.append(0.0)
        else:
            rates.append(bins[i] / bin_hours[i])

    mean_rate = total / 168.0
    if mean_rate == 0:
        return [1.0, 1.0, 1.0]

    return [r / mean_rate if mean_rate > 0 else 1.0 for r in rates]


def build_profile(
    rule_class: str,
    event_hours: list[int],
    config: TuningConfig | None = None,
) -> SeasonalityProfile:
    """Build a seasonality profile for a rule class from 90d event data."""
    cfg = config or TuningConfig()
    n = len(event_hours)
    use_bins = n < cfg.seasonality_min_events

    hourly = estimate_hourly_profile(event_hours) if not use_bins else [1.0] * 168
    bins = estimate_bin_profile(event_hours, cfg)

    return SeasonalityProfile(
        rule_class=rule_class,
        hourly=hourly,
        bins=bins,
        total_events_90d=n,
    )


def effective_exposure(
    observation_hours: list[int],
    profile: SeasonalityProfile,
    config: TuningConfig | None = None,
) -> float:
    """Compute effective exposure T_star = sum of s(h(t)) over observation hours.

    Args:
        observation_hours: Hour-of-week indices for each hour of the observation window.
        profile: Seasonality profile for the rule class.
        config: Tuning config (for seasonality_min_events threshold).

    Returns:
        T_star in effective hours.
    """
    cfg = config or TuningConfig()
    use_bins = profile.total_events_90d < cfg.seasonality_min_events

    t_star = 0.0
    for h in observation_hours:
        t_star += profile.multiplier(h % 168, use_bins=use_bins)
    return t_star


def _bin_index(
    hour_of_week: int,
    biz_start: int,
    biz_end: int,
    biz_days: set[int],
) -> int:
    """Map hour-of-week to bin index: 0=business, 1=evening, 2=weekend."""
    day = hour_of_week // 24
    hour = hour_of_week % 24
    if day not in biz_days:
        return 2
    if biz_start <= hour < biz_end:
        return 0
    return 1
