"""Test 5: Decay preserves posterior mean and widens variance."""

from datetime import date

import pytest

from kahu_tuning.config import TuningConfig
from kahu_tuning.decay import apply_decay
from kahu_tuning.models import TupleState, WindowState


class TestExponentialDecay:
    def test_mean_preserved(self):
        """Decay preserves posterior mean (alpha/beta ratio unchanged)."""
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=10.0, beta=5.0),
            w_24h=WindowState(alpha=20.0, beta=10.0),
            w_7d=WindowState(alpha=100.0, beta=50.0),
            w_90d=WindowState(alpha=500.0, beta=250.0),
            golden_alpha=500.0,
            golden_beta=250.0,
        )

        mean_before = state.w_90d.posterior_mean
        decayed = apply_decay(state, today=date(2026, 7, 21))
        mean_after = decayed.w_90d.posterior_mean

        assert mean_after == pytest.approx(mean_before, rel=1e-10)

    def test_variance_increases(self):
        """Decay widens posterior variance."""
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=10.0, beta=5.0),
            w_24h=WindowState(alpha=20.0, beta=10.0),
            w_7d=WindowState(alpha=100.0, beta=50.0),
            w_90d=WindowState(alpha=500.0, beta=250.0),
            golden_alpha=500.0,
            golden_beta=250.0,
        )

        var_before = state.w_90d.posterior_variance
        decayed = apply_decay(state, today=date(2026, 7, 21))
        var_after = decayed.w_90d.posterior_variance

        assert var_after > var_before

    def test_golden_not_decayed(self):
        """Golden snapshot is never decayed."""
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=10.0, beta=5.0),
            w_24h=WindowState(alpha=10.0, beta=5.0),
            w_7d=WindowState(alpha=10.0, beta=5.0),
            w_90d=WindowState(alpha=10.0, beta=5.0),
            golden_alpha=100.0,
            golden_beta=50.0,
        )

        decayed = apply_decay(state, today=date(2026, 7, 21))
        assert decayed.golden_alpha == 100.0
        assert decayed.golden_beta == 50.0

    def test_idempotent_same_day(self):
        """Decay is idempotent within the same calendar day."""
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=10.0, beta=5.0),
            w_24h=WindowState(alpha=10.0, beta=5.0),
            w_7d=WindowState(alpha=10.0, beta=5.0),
            w_90d=WindowState(alpha=10.0, beta=5.0),
            golden_alpha=10.0,
            golden_beta=5.0,
        )

        d = date(2026, 7, 21)
        first = apply_decay(state, today=d)
        second = apply_decay(first, today=d)

        # Second decay should be no-op
        assert second.w_90d.alpha == pytest.approx(first.w_90d.alpha)
        assert second.w_90d.beta == pytest.approx(first.w_90d.beta)

    def test_decay_factor(self):
        """Alpha and beta are multiplied by delta."""
        config = TuningConfig(decay_delta=0.992)
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=100.0, beta=50.0),
            w_24h=WindowState(alpha=100.0, beta=50.0),
            w_7d=WindowState(alpha=100.0, beta=50.0),
            w_90d=WindowState(alpha=100.0, beta=50.0),
            golden_alpha=100.0,
            golden_beta=50.0,
        )

        decayed = apply_decay(state, today=date(2026, 7, 21), config=config)
        assert decayed.w_90d.alpha == pytest.approx(100.0 * 0.992)
        assert decayed.w_90d.beta == pytest.approx(50.0 * 0.992)

    def test_multiple_days_compound(self):
        """Decay compounds over multiple days."""
        config = TuningConfig(decay_delta=0.992)
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(alpha=100.0, beta=50.0),
            w_24h=WindowState(alpha=100.0, beta=50.0),
            w_7d=WindowState(alpha=100.0, beta=50.0),
            w_90d=WindowState(alpha=100.0, beta=50.0),
            golden_alpha=100.0,
            golden_beta=50.0,
        )

        d1 = apply_decay(state, today=date(2026, 7, 21), config=config)
        d2 = apply_decay(d1, today=date(2026, 7, 22), config=config)

        expected_alpha = 100.0 * 0.992 * 0.992
        assert d2.w_90d.alpha == pytest.approx(expected_alpha)
