"""Bayes factor decision rule using negative binomial marginal likelihood."""

from __future__ import annotations

from math import lgamma, log

from kahu_tuning.config import TuningConfig


def log_marginal_likelihood(
    n: int,
    alpha: float,
    beta: float,
    t_star: float,
) -> float:
    """Log marginal likelihood under Gamma-Poisson model (negative binomial form).

    log m(N | alpha, beta) = lgamma(N + alpha) - lgamma(alpha) - lgamma(N + 1)
                            + alpha * (log(beta) - log(beta + T_star))
                            + N * (log(T_star) - log(beta + T_star))

    All computation in log space for numerical stability.
    """
    if beta <= 0 or t_star <= 0 or alpha <= 0:
        return float("-inf")

    log_beta = log(beta)
    log_beta_t = log(beta + t_star)
    log_t = log(t_star)

    return (
        lgamma(n + alpha)
        - lgamma(alpha)
        - lgamma(n + 1)
        + alpha * (log_beta - log_beta_t)
        + n * (log_t - log_beta_t)
    )


def log_bayes_factor_01(
    n: int,
    alpha0: float,
    beta0: float,
    t_star: float,
    gamma: float = 3.0,
) -> float:
    """Log Bayes factor BF01: H0 (benign) vs H1 (elevated).

    H0: lambda ~ Gamma(alpha0, beta0) -- hierarchical posterior from long windows
    H1: lambda ~ Gamma(alpha0, beta0 / gamma) -- elevated rate hypothesis

    Returns log(BF01) = log(m_H0) - log(m_H1).
    Positive values favor H0 (benign), negative favor H1 (elevated).
    """
    log_m0 = log_marginal_likelihood(n, alpha0, beta0, t_star)
    log_m1 = log_marginal_likelihood(n, alpha0, beta0 / gamma, t_star)
    return log_m0 - log_m1


def posterior_odds(
    log_bf01: float,
    prior_odds: float = 1.0,
) -> float:
    """Posterior odds of H0 (benign) = BF01 * prior_odds.

    High posterior odds means strong evidence for benign behavior.
    Low posterior odds means alert rate is elevated.
    """
    from math import exp

    # Clamp to avoid overflow
    log_po = log_bf01 + log(prior_odds) if prior_odds > 0 else log_bf01
    if log_po > 500:
        return float("inf")
    if log_po < -500:
        return 0.0
    return exp(log_po)


def should_suppress(
    n: int,
    alpha0: float,
    beta0: float,
    t_star: float,
    risk_multiplier: float = 1.0,
    config: TuningConfig | None = None,
) -> tuple[bool, float, float, float]:
    """Evaluate whether a tuple should be suppressed.

    Returns:
        (suppress, posterior_odds, log_bf01, threshold_applied)
    """
    cfg = config or TuningConfig()
    gamma = cfg.gamma_elevated
    prior = cfg.prior_odds
    theta_base = cfg.theta_base

    log_bf = log_bayes_factor_01(n, alpha0, beta0, t_star, gamma)
    po = posterior_odds(log_bf, prior)
    threshold = theta_base * risk_multiplier

    return po >= threshold, po, log_bf, threshold
