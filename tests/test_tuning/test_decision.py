"""Tests for Bayes factor decision rule and log-space stability."""

import math

import pytest

from kahu_tuning.config import TuningConfig
from kahu_tuning.decision import (
    log_bayes_factor_01,
    log_marginal_likelihood,
    posterior_odds,
    should_suppress,
)


class TestLogMarginalLikelihood:
    def test_basic_computation(self):
        """Log marginal likelihood is finite for reasonable inputs."""
        lml = log_marginal_likelihood(n=10, alpha=2.0, beta=1.0, t_star=24.0)
        assert math.isfinite(lml)

    def test_zero_events(self):
        """N=0 produces a finite log marginal likelihood."""
        lml = log_marginal_likelihood(n=0, alpha=1.0, beta=1.0, t_star=10.0)
        assert math.isfinite(lml)

    def test_large_n_finite(self):
        """Acceptance test 6: BF computations finite for N up to 10^7."""
        lml = log_marginal_likelihood(n=10_000_000, alpha=1.0, beta=1.0, t_star=720.0)
        assert math.isfinite(lml)

    def test_large_n_bf_finite(self):
        """BF01 remains finite for N=10^7."""
        log_bf = log_bayes_factor_01(
            n=10_000_000, alpha0=1.0, beta0=1.0, t_star=720.0, gamma=3.0,
        )
        assert math.isfinite(log_bf)

    def test_very_large_n_bf_finite(self):
        """BF01 finite even at extreme N values."""
        log_bf = log_bayes_factor_01(
            n=10_000_000, alpha0=0.5, beta0=0.5, t_star=2160.0, gamma=3.0,
        )
        assert math.isfinite(log_bf)

    def test_invalid_inputs(self):
        """Invalid inputs return -inf."""
        assert log_marginal_likelihood(n=10, alpha=0, beta=1.0, t_star=1.0) == float("-inf")
        assert log_marginal_likelihood(n=10, alpha=1.0, beta=0, t_star=1.0) == float("-inf")
        assert log_marginal_likelihood(n=10, alpha=1.0, beta=1.0, t_star=0) == float("-inf")


class TestBayesFactor:
    def test_benign_tuple_high_bf(self):
        """Consistently low-rate tuple should have high BF01 (favors benign)."""
        # Long history of low rate: 100 events over 2160 hours
        log_bf = log_bayes_factor_01(
            n=100, alpha0=50.0, beta0=1000.0, t_star=2160.0, gamma=3.0,
        )
        # BF01 should be positive (favors H0/benign)
        assert log_bf > 0

    def test_elevated_tuple_low_bf(self):
        """Elevated rate should produce low BF01 (favors elevated hypothesis)."""
        # Sudden burst: 500 events in 24 hours, but prior says ~2/hour
        log_bf = log_bayes_factor_01(
            n=500, alpha0=2.0, beta0=1.0, t_star=24.0, gamma=3.0,
        )
        # BF01 should be negative (favors H1/elevated)
        assert log_bf < 0


class TestPosteriorOdds:
    def test_neutral_prior(self):
        """With prior_odds=1, posterior odds = BF01."""
        po = posterior_odds(log_bf01=2.0, prior_odds=1.0)
        assert po == pytest.approx(math.exp(2.0))

    def test_overflow_clamped(self):
        """Extreme positive log BF returns inf, not crash."""
        po = posterior_odds(log_bf01=600.0, prior_odds=1.0)
        assert po == float("inf")

    def test_underflow_clamped(self):
        """Extreme negative log BF returns 0, not crash."""
        po = posterior_odds(log_bf01=-600.0, prior_odds=1.0)
        assert po == 0.0


class TestShouldSuppress:
    def test_risk_multiplier_r1_clears(self):
        """Acceptance test 4a: identical evidence clears threshold at r=1."""
        # Moderate benign evidence: prior rate ~2/hr, observe consistent rate
        suppress, po, _, threshold = should_suppress(
            n=48,
            alpha0=10.0,
            beta0=5.0,
            t_star=24.0,
            risk_multiplier=1.0,
        )
        assert suppress is True
        assert po >= threshold

    def test_risk_multiplier_r12500_fails(self):
        """Acceptance test 4b: identical evidence fails at r=12500."""
        suppress, po, _, threshold = should_suppress(
            n=48,
            alpha0=10.0,
            beta0=5.0,
            t_star=24.0,
            risk_multiplier=12500.0,
        )
        assert suppress is False
        assert po < threshold

    def test_threshold_scales_with_risk(self):
        """Threshold = theta_base * risk_multiplier."""
        config = TuningConfig(theta_base=20.0)
        _, _, _, t1 = should_suppress(
            n=10, alpha0=1.0, beta0=1.0, t_star=24.0,
            risk_multiplier=1.0, config=config,
        )
        _, _, _, t2 = should_suppress(
            n=10, alpha0=1.0, beta0=1.0, t_star=24.0,
            risk_multiplier=5.0, config=config,
        )
        assert t1 == pytest.approx(20.0)
        assert t2 == pytest.approx(100.0)
