"""Test 1: Conjugate update correctness against closed-form values."""

import pytest

from kahu_tuning.conjugate import (
    gamma_poisson_update,
    posterior_mean,
    posterior_variance,
    update_window,
)
from kahu_tuning.models import WindowState


class TestGammaPoissonUpdate:
    def test_basic_update(self):
        """Posterior alpha = prior_alpha + N, posterior beta = prior_beta + T."""
        a, b = gamma_poisson_update(1.0, 1.0, n_events=10, t_star_hours=5.0)
        assert a == 11.0
        assert b == 6.0

    def test_zero_events(self):
        """No events: alpha unchanged, beta increases by exposure."""
        a, b = gamma_poisson_update(2.0, 3.0, n_events=0, t_star_hours=10.0)
        assert a == 2.0
        assert b == 13.0

    def test_posterior_mean_formula(self):
        """Posterior mean = alpha / beta."""
        a, b = gamma_poisson_update(1.0, 1.0, n_events=10, t_star_hours=5.0)
        mean = posterior_mean(a, b)
        assert mean == pytest.approx(11.0 / 6.0)

    def test_posterior_variance_formula(self):
        """Posterior variance = alpha / beta^2."""
        a, b = gamma_poisson_update(1.0, 1.0, n_events=10, t_star_hours=5.0)
        var = posterior_variance(a, b)
        assert var == pytest.approx(11.0 / 36.0)

    def test_sequential_updates_equal_batch(self):
        """Two sequential updates should equal one batch update."""
        # Batch: observe 15 events in 10 hours total
        a_batch, b_batch = gamma_poisson_update(1.0, 1.0, 15, 10.0)

        # Sequential: 10 events in 6h, then 5 events in 4h
        a1, b1 = gamma_poisson_update(1.0, 1.0, 10, 6.0)
        a2, b2 = gamma_poisson_update(a1, b1, 5, 4.0)

        assert a2 == pytest.approx(a_batch)
        assert b2 == pytest.approx(b_batch)

    def test_large_n(self):
        """Update works with very large event counts."""
        a, b = gamma_poisson_update(0.5, 0.5, n_events=10_000_000, t_star_hours=720.0)
        assert a == pytest.approx(10_000_000.5)
        assert b == pytest.approx(720.5)
        # Mean should be close to empirical rate (prior contributes ~0.07%)
        assert posterior_mean(a, b) == pytest.approx(10_000_000.5 / 720.5, rel=1e-6)

    def test_update_window_object(self):
        """update_window returns correct WindowState."""
        w = WindowState(alpha=1.0, beta=1.0, n_events=0, t_hours=0.0)
        w2 = update_window(w, n_events=5, t_star_hours=2.0)
        assert w2.alpha == 6.0
        assert w2.beta == 3.0
        assert w2.n_events == 5
        assert w2.t_hours == 2.0
        assert w2.posterior_mean == pytest.approx(2.0)

    def test_weakly_informative_prior(self):
        """With Gamma(0.5, 0.5) prior, posterior mean converges to MLE."""
        a, b = gamma_poisson_update(0.5, 0.5, n_events=1000, t_star_hours=100.0)
        mle = 1000 / 100.0
        assert posterior_mean(a, b) == pytest.approx(mle, rel=0.01)
