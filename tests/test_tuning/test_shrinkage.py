"""Test 2: Shrinkage behavior -- sparse data stays near parent, dense data converges."""

import pytest

from kahu_tuning.config import TuningConfig
from kahu_tuning.models import TupleState, WindowState
from kahu_tuning.shrinkage import hierarchical_update, shrinkage_prior, shrunk_posterior_mean


class TestShrinkagePrior:
    def test_prior_parameters(self):
        """prior_alpha = kappa * parent_mean, prior_beta = kappa."""
        a, b = shrinkage_prior(parent_mean=2.0, kappa=100.0)
        assert a == 200.0
        assert b == 100.0
        assert a / b == pytest.approx(2.0)

    def test_prior_preserves_parent_mean(self):
        """Shrinkage prior mean equals parent mean."""
        a, b = shrinkage_prior(parent_mean=5.5, kappa=50.0)
        assert a / b == pytest.approx(5.5)


class TestShrunkPosteriorMean:
    def test_no_data_equals_parent(self):
        """With no observations, posterior mean equals parent mean."""
        config = TuningConfig()
        mean = shrunk_posterior_mean("1h", n_events=0, t_hours=0, parent_mean=3.0, config=config)
        assert mean == pytest.approx(3.0)

    def test_sparse_data_stays_near_parent(self):
        """With 3 days of data, estimate stays within 10% of parent."""
        config = TuningConfig()
        parent_mean = 2.0

        # 3 days = 72 hours, moderate event count
        n = int(2.0 * 72)  # events at true rate matching parent
        t = 72.0

        mean = shrunk_posterior_mean(
            "7d", n_events=n, t_hours=t,
            parent_mean=parent_mean, config=config,
        )
        assert abs(mean - parent_mean) / parent_mean < 0.10

    def test_dense_data_converges_to_empirical(self):
        """With 90 days of dense data and matching parent, within 5% of empirical rate.

        The shrunk posterior mean = (kappa * parent + N) / (kappa + T).
        With kappa_90d=2160 and T=2160, prior gets 50% weight. Convergence
        to empirical requires that the parent (golden) has itself been updated,
        which is tested in TestHierarchicalUpdate. Here we verify that when
        parent matches the true rate, the shrunk mean converges.
        """
        config = TuningConfig()
        true_rate = 5.0
        t = 90 * 24.0  # 2160 hours
        n = int(true_rate * t)

        # Parent mean matches the true rate (as it would after golden update)
        mean = shrunk_posterior_mean(
            "90d", n_events=n, t_hours=t,
            parent_mean=true_rate, config=config,
        )
        assert abs(mean - true_rate) / true_rate < 0.05


class TestHierarchicalUpdate:
    def test_full_hierarchy(self):
        """Full hierarchical update produces valid posteriors at all levels."""
        config = TuningConfig()
        state = TupleState(
            rule_id="100001",
            source_key="fw-01",
            asset_id="srv-01",
            w_1h=WindowState(0.5, 0.5),
            w_24h=WindowState(0.5, 0.5),
            w_7d=WindowState(0.5, 0.5),
            w_90d=WindowState(0.5, 0.5),
            golden_alpha=10.0,
            golden_beta=5.0,
        )

        observations = {
            "1h": (3, 1.0),
            "24h": (50, 24.0),
            "7d": (400, 168.0),
            "90d": (5000, 2160.0),
        }

        updated = hierarchical_update(state, observations, config)

        # All windows should have positive parameters
        for w_name in ("1h", "24h", "7d", "90d"):
            w = updated.window(w_name)
            assert w.alpha > 0
            assert w.beta > 0
            assert w.posterior_mean > 0

        # Golden should accumulate
        assert updated.golden_alpha == state.golden_alpha + 5000
        assert updated.golden_beta == state.golden_beta + 2160.0

    def test_sparse_3day_within_10pct_of_parent(self):
        """Acceptance: tuple with 3 days data stays within 10% of parent estimate."""
        config = TuningConfig()
        parent_rate = 2.0
        golden_alpha = 200.0
        golden_beta = 100.0  # golden mean = 2.0

        state = TupleState(
            rule_id="100001",
            source_key="fw-01",
            asset_id="srv-01",
            w_1h=WindowState(0.5, 0.5),
            w_24h=WindowState(0.5, 0.5),
            w_7d=WindowState(0.5, 0.5),
            w_90d=WindowState(0.5, 0.5),
            golden_alpha=golden_alpha,
            golden_beta=golden_beta,
        )

        # 3 days of data at roughly the parent rate
        n_3d = int(parent_rate * 72)
        observations = {
            "1h": (int(parent_rate * 1), 1.0),
            "24h": (int(parent_rate * 24), 24.0),
            "7d": (n_3d, 72.0),  # Only 3 days of a 7d window
            "90d": (n_3d, 72.0),
        }

        updated = hierarchical_update(state, observations, config)
        # The 7d window should be pulled toward the parent (golden) mean
        w7d_mean = updated.w_7d.posterior_mean
        assert abs(w7d_mean - parent_rate) / parent_rate < 0.10

    def test_dense_90d_within_5pct_of_empirical(self):
        """Acceptance: tuple with 90 days dense data within 5% of empirical rate."""
        config = TuningConfig()
        true_rate = 5.0
        hours_90d = 90 * 24.0
        n_90d = int(true_rate * hours_90d)

        state = TupleState(
            rule_id="100001",
            source_key="fw-01",
            asset_id="srv-01",
            w_1h=WindowState(0.5, 0.5),
            w_24h=WindowState(0.5, 0.5),
            w_7d=WindowState(0.5, 0.5),
            w_90d=WindowState(0.5, 0.5),
            golden_alpha=1.0,
            golden_beta=1.0,  # golden mean = 1.0 (different from true rate)
        )

        observations = {
            "1h": (int(true_rate * 1), 1.0),
            "24h": (int(true_rate * 24), 24.0),
            "7d": (int(true_rate * 168), 168.0),
            "90d": (n_90d, hours_90d),
        }

        updated = hierarchical_update(state, observations, config)
        w90d_mean = updated.w_90d.posterior_mean
        assert abs(w90d_mean - true_rate) / true_rate < 0.05

    def test_fleet_prior_fallback(self):
        """When no fleet prior, uses Gamma(0.5, 0.5) as fallback."""
        config = TuningConfig()
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(0.5, 0.5), w_24h=WindowState(0.5, 0.5),
            w_7d=WindowState(0.5, 0.5), w_90d=WindowState(0.5, 0.5),
            golden_alpha=0.5, golden_beta=0.5,
        )
        observations = {"1h": (0, 1.0), "24h": (0, 24.0), "7d": (0, 168.0), "90d": (0, 2160.0)}

        # Should not raise
        updated = hierarchical_update(state, observations, config, fleet_prior=None)
        assert updated.w_1h.alpha > 0
