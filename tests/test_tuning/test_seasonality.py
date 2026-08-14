"""Tests for seasonality estimation and effective exposure."""

import pytest

from kahu_tuning.config import TuningConfig
from kahu_tuning.models import SeasonalityProfile
from kahu_tuning.seasonality import (
    build_profile,
    effective_exposure,
    estimate_bin_profile,
    estimate_hourly_profile,
)


class TestHourlyProfile:
    def test_uniform_events(self):
        """Uniform events produce flat profile (all 1.0)."""
        # One event in each hour of the week
        hours = list(range(168))
        profile = estimate_hourly_profile(hours)
        assert len(profile) == 168
        for m in profile:
            assert m == pytest.approx(1.0)

    def test_concentrated_events(self):
        """Events concentrated in one hour produce high multiplier there."""
        hours = [10] * 100  # all events at hour 10
        profile = estimate_hourly_profile(hours)
        assert profile[10] > 100  # much higher than mean
        assert profile[0] == pytest.approx(0.0)

    def test_empty_events(self):
        """No events produce flat profile."""
        profile = estimate_hourly_profile([])
        assert all(m == 1.0 for m in profile)

    def test_normalized_mean_one(self):
        """Profile multipliers average to 1.0."""
        import random
        rng = random.Random(42)  # noqa: S311
        hours = [rng.randint(0, 167) for _ in range(10000)]
        profile = estimate_hourly_profile(hours)
        mean = sum(profile) / 168
        assert mean == pytest.approx(1.0, abs=0.05)


class TestBinProfile:
    def test_all_business_hours(self):
        """Events only during business hours boost that bin."""
        # Business hours: Mon-Fri 07:00-17:00
        hours = []
        for day in range(5):  # Mon-Fri
            for h in range(7, 18):
                hours.extend([day * 24 + h] * 10)

        bins = estimate_bin_profile(hours)
        assert bins[0] > bins[1]  # business > evening
        assert bins[0] > bins[2]  # business > weekend

    def test_empty_events(self):
        """No events produce flat bins."""
        bins = estimate_bin_profile([])
        assert bins == [1.0, 1.0, 1.0]


class TestBuildProfile:
    def test_enough_events_uses_hourly(self):
        """With >= 500 events, profile uses hourly granularity."""
        hours = list(range(168)) * 4  # 672 events
        profile = build_profile("test_rule", hours)
        assert profile.total_events_90d == 672

    def test_sparse_events_uses_bins(self):
        """With < 500 events, profile uses 3-bin fallback."""
        hours = list(range(100))
        profile = build_profile("test_rule", hours)
        assert profile.total_events_90d == 100


class TestEffectiveExposure:
    def test_flat_profile(self):
        """Flat profile: T_star = number of observation hours."""
        profile = SeasonalityProfile(
            rule_class="test",
            hourly=[1.0] * 168,
            total_events_90d=1000,
        )
        obs_hours = list(range(24))  # 24 hours
        t_star = effective_exposure(obs_hours, profile)
        assert t_star == pytest.approx(24.0)

    def test_scaled_profile(self):
        """Non-uniform profile adjusts effective exposure."""
        hourly = [2.0] * 84 + [0.0] * 84  # half the week is 2x, half is 0x
        profile = SeasonalityProfile(
            rule_class="test",
            hourly=hourly,
            total_events_90d=1000,
        )
        # Observe during the active half
        obs_hours = list(range(84))
        t_star = effective_exposure(obs_hours, profile)
        assert t_star == pytest.approx(84 * 2.0)

    def test_bin_fallback(self):
        """With sparse data, uses bin profile."""
        profile = SeasonalityProfile(
            rule_class="test",
            bins=[2.0, 0.5, 0.5],
            total_events_90d=100,  # below threshold
        )
        config = TuningConfig(seasonality_min_events=500)
        # Business hour on Monday
        obs_hours = [7 + 0 * 24]  # Monday 07:00 = hour_of_week 7, bin 0 (business)
        t_star = effective_exposure(obs_hours, profile, config=config)
        assert t_star == pytest.approx(2.0)
