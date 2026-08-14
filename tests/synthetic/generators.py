"""Synthetic data generators for tuning engine tests."""

from __future__ import annotations

import random

from kahu_tuning.models import FleetPrior, SeasonalityProfile, TupleState, WindowState


def make_tuple_state(
    rule_id: str = "100001",
    source_key: str = "firewall-01",
    asset_id: str = "srv-web-01",
    alpha: float = 0.5,
    beta: float = 0.5,
) -> TupleState:
    """Create a fresh TupleState with uniform priors."""
    WindowState(alpha=alpha, beta=beta)
    return TupleState(
        rule_id=rule_id,
        source_key=source_key,
        asset_id=asset_id,
        w_1h=WindowState(alpha=alpha, beta=beta),
        w_24h=WindowState(alpha=alpha, beta=beta),
        w_7d=WindowState(alpha=alpha, beta=beta),
        w_90d=WindowState(alpha=alpha, beta=beta),
        golden_alpha=alpha,
        golden_beta=beta,
    )


def generate_poisson_events(
    rate: float,
    hours: int,
    seed: int = 42,
) -> list[int]:
    """Generate Poisson-distributed event counts per hour.

    Args:
        rate: Events per hour (lambda).
        hours: Number of hours to simulate.
        seed: Random seed for reproducibility.

    Returns:
        List of event counts, one per hour.
    """
    rng = random.Random(seed)  # noqa: S311
    counts = []
    for _ in range(hours):
        # Poisson via inverse CDF
        n = 0
        p = 1.0
        rng.random()
        import math
        threshold = math.exp(-rate)
        while p > threshold:
            n += 1
            p *= rng.random()
        counts.append(n - 1 if n > 0 else 0)
    return counts


def generate_ramping_events(
    start_rate: float,
    end_rate: float,
    days: int,
    seed: int = 42,
) -> list[tuple[int, int]]:
    """Generate events with linearly ramping rate over days.

    Returns:
        List of (day_index, event_count_for_day) tuples.
    """
    rng = random.Random(seed)  # noqa: S311
    import math
    result = []
    for d in range(days):
        frac = d / max(days - 1, 1)
        rate = start_rate + (end_rate - start_rate) * frac
        daily_rate = rate * 24  # convert hourly to daily
        # Poisson sample
        n = 0
        p = 1.0
        threshold = math.exp(-daily_rate) if daily_rate < 700 else 0.0
        if threshold > 0:
            while p > threshold:
                n += 1
                p *= rng.random()
            n = max(0, n - 1)
        else:
            # For high rates, use normal approximation
            n = max(0, int(rng.gauss(daily_rate, daily_rate ** 0.5)))
        result.append((d, n))
    return result


def flat_seasonality(rule_class: str = "default") -> SeasonalityProfile:
    """Seasonality profile with no variation (all multipliers = 1)."""
    return SeasonalityProfile(
        rule_class=rule_class,
        hourly=[1.0] * 168,
        bins=[1.0, 1.0, 1.0],
        total_events_90d=1000,
    )


def default_fleet_prior() -> FleetPrior:
    """Weakly informative fleet prior."""
    return FleetPrior(alpha=0.5, beta=0.5, source="default")
