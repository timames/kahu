"""Hierarchical shrinkage across time windows."""

from __future__ import annotations

from kahu_tuning.config import TuningConfig
from kahu_tuning.conjugate import posterior_mean
from kahu_tuning.models import FleetPrior, TupleState, WindowState

# Window hierarchy: 1h <- 24h <- 7d <- 90d <- golden <- fleet
WINDOW_ORDER = ("1h", "24h", "7d", "90d")
PARENT_MAP = {
    "1h": "24h",
    "24h": "7d",
    "7d": "90d",
    "90d": "golden",
}


def shrinkage_prior(
    parent_mean: float,
    kappa: float,
) -> tuple[float, float]:
    """Compute shrinkage prior from parent posterior mean.

    prior_alpha = kappa * lambda_hat_parent
    prior_beta = kappa
    """
    return kappa * parent_mean, kappa


def hierarchical_update(
    state: TupleState,
    observations: dict[str, tuple[int, float]],
    config: TuningConfig,
    fleet_prior: FleetPrior | None = None,
) -> TupleState:
    """Update all windows with hierarchical shrinkage.

    Args:
        state: Current tuple state.
        observations: {window_name: (n_events, t_star_hours)} for each window.
        config: Tuning configuration.
        fleet_prior: Fleet-level prior (falls back to weakly informative).

    Returns:
        Updated TupleState with new posteriors.
    """
    fp = fleet_prior or FleetPrior()

    # Fleet mean as parent for golden
    fleet_mean = fp.alpha / fp.beta if fp.beta > 0 else 1.0

    # Update golden first so we use the fresh posterior as 90d's parent
    n_90d, t_90d = observations.get("90d", (0, 0.0))
    new_golden_alpha = state.golden_alpha + n_90d
    new_golden_beta = state.golden_beta + t_90d
    golden_mean = posterior_mean(new_golden_alpha, new_golden_beta)
    if golden_mean <= 0:
        golden_mean = fleet_mean

    # For 90d, parent is golden; for 7d parent is 90d, etc.
    # But we need the *current* posterior means to serve as parents for children.
    # Process top-down: 90d first (parent=golden), then 7d, 24h, 1h.
    new_windows: dict[str, WindowState] = {}

    for window_name in reversed(WINDOW_ORDER):
        parent_key = PARENT_MAP[window_name]
        if parent_key == "golden":
            parent_lambda = golden_mean
        elif parent_key in new_windows:
            parent_lambda = new_windows[parent_key].posterior_mean
        else:
            parent_lambda = fleet_mean

        if parent_lambda <= 0:
            parent_lambda = fleet_mean

        kappa = config.kappa_for_window(window_name)
        prior_alpha, prior_beta = shrinkage_prior(parent_lambda, kappa)

        n, t = observations.get(window_name, (0, 0.0))

        # Posterior: shrinkage prior + data
        # posterior_mean = (kappa * lambda_hat_parent + N) / (kappa + T)
        post_alpha = prior_alpha + n
        post_beta = prior_beta + t

        new_windows[window_name] = WindowState(
            alpha=post_alpha,
            beta=post_beta,
            n_events=n,
            t_hours=t,
        )

    return TupleState(
        rule_id=state.rule_id,
        source_key=state.source_key,
        asset_id=state.asset_id,
        w_1h=new_windows["1h"],
        w_24h=new_windows["24h"],
        w_7d=new_windows["7d"],
        w_90d=new_windows["90d"],
        golden_alpha=new_golden_alpha,
        golden_beta=new_golden_beta,
        last_decay_ts=state.last_decay_ts,
        last_update_ts=state.last_update_ts,
    )


def shrunk_posterior_mean(
    window_name: str,
    n_events: int,
    t_hours: float,
    parent_mean: float,
    config: TuningConfig,
) -> float:
    """Compute the shrunk posterior mean for a single window.

    posterior_mean = (kappa * lambda_hat_parent + N) / (kappa + T)
    """
    kappa = config.kappa_for_window(window_name)
    return (kappa * parent_mean + n_events) / (kappa + t_hours)
