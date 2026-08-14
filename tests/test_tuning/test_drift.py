"""Tests for KL divergence drift detection."""


import pytest

from kahu_tuning.drift import check_drift, gamma_kl


class TestGammaKL:
    def test_identical_distributions_zero_kl(self):
        """KL divergence of identical distributions is zero."""
        kl = gamma_kl(2.0, 3.0, 2.0, 3.0)
        assert kl == pytest.approx(0.0, abs=1e-10)

    def test_positive_definite(self):
        """KL divergence is always non-negative."""
        kl = gamma_kl(2.0, 3.0, 5.0, 1.0)
        assert kl >= 0

    def test_asymmetric(self):
        """KL(p || q) != KL(q || p) in general."""
        kl_pq = gamma_kl(2.0, 3.0, 5.0, 1.0)
        kl_qp = gamma_kl(5.0, 1.0, 2.0, 3.0)
        assert kl_pq != pytest.approx(kl_qp)

    def test_large_divergence(self):
        """Very different distributions have large KL."""
        kl = gamma_kl(100.0, 1.0, 1.0, 100.0)
        assert kl > 10.0

    def test_invalid_params(self):
        """Invalid parameters return inf."""
        assert gamma_kl(0, 1.0, 1.0, 1.0) == float("inf")
        assert gamma_kl(1.0, 0, 1.0, 1.0) == float("inf")


class TestCheckDrift:
    def test_no_drift_identical(self):
        """Identical distributions do not trigger drift."""
        drift, kl = check_drift(2.0, 3.0, 2.0, 3.0)
        assert drift is False
        assert kl == pytest.approx(0.0, abs=1e-10)

    def test_drift_elevated_rate(self):
        """Elevated 90d rate vs stable golden triggers drift."""
        # Golden: mean = 1.0 (alpha=10, beta=10)
        # 90d: mean = 5.0 (alpha=50, beta=10) -- rate jumped significantly
        drift, kl = check_drift(
            alpha_90d=50.0, beta_90d=10.0,
            alpha_golden=10.0, beta_golden=10.0,
            epsilon=0.5,
        )
        assert drift is True
        assert kl > 0.5

    def test_no_drift_decreased_rate(self):
        """Decreased 90d rate does not trigger drift (mean condition)."""
        # Golden: mean = 5.0; 90d: mean = 1.0 -- rate went DOWN
        drift, kl = check_drift(
            alpha_90d=10.0, beta_90d=10.0,
            alpha_golden=50.0, beta_golden=10.0,
            epsilon=0.5,
        )
        # Even if KL is large, drift should not fire because mean_90d < mean_golden
        assert drift is False

    def test_slow_poisoning(self):
        """Acceptance test 3 (part): gradually elevated rate triggers drift."""
        # Golden: rate = 1.0 events/hr, well-established
        golden_alpha = 1000.0
        golden_beta = 1000.0  # mean = 1.0

        # 90d window: rate has crept up to 3.0
        alpha_90d = 3000.0
        beta_90d = 1000.0  # mean = 3.0

        drift, kl = check_drift(
            alpha_90d=alpha_90d, beta_90d=beta_90d,
            alpha_golden=golden_alpha, beta_golden=golden_beta,
            epsilon=0.5,
        )
        assert drift is True
        assert kl > 0.5
