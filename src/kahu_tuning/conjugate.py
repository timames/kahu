"""Gamma-Poisson conjugate updates."""

from __future__ import annotations

from kahu_tuning.models import WindowState


def gamma_poisson_update(
    prior_alpha: float,
    prior_beta: float,
    n_events: int,
    t_star_hours: float,
) -> tuple[float, float]:
    """Posterior Gamma parameters after observing n_events in t_star_hours.

    Likelihood: N ~ Poisson(lambda * T_star)
    Prior: lambda ~ Gamma(alpha, beta)
    Posterior: lambda ~ Gamma(alpha + N, beta + T_star)
    """
    return prior_alpha + n_events, prior_beta + t_star_hours


def update_window(
    window: WindowState,
    n_events: int,
    t_star_hours: float,
) -> WindowState:
    """Apply conjugate update to a window and return updated copy."""
    new_alpha, new_beta = gamma_poisson_update(
        window.alpha, window.beta, n_events, t_star_hours,
    )
    return WindowState(
        alpha=new_alpha,
        beta=new_beta,
        n_events=window.n_events + n_events,
        t_hours=window.t_hours + t_star_hours,
    )


def posterior_mean(alpha: float, beta: float) -> float:
    if beta == 0:
        return 0.0
    return alpha / beta


def posterior_variance(alpha: float, beta: float) -> float:
    if beta == 0:
        return 0.0
    return alpha / (beta ** 2)
