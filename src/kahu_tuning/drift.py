"""KL divergence drift detection between 90d and golden posteriors."""

from __future__ import annotations

from math import log

from scipy.special import digamma as psi  # type: ignore[import-untyped]
from scipy.special import gammaln  # type: ignore[import-untyped]


def gamma_kl(
    a_p: float,
    b_p: float,
    a_q: float,
    b_q: float,
) -> float:
    """KL divergence KL(Gamma(a_p, b_p) || Gamma(a_q, b_q)).

    Closed-form using digamma (psi) and lgamma:

    KL(p || q) = (a_p - a_q) * psi(a_p) - lgamma(a_p) + lgamma(a_q)
               + a_q * (log(b_p) - log(b_q)) + a_p * (b_q - b_p) / b_p

    Note: This uses the rate parameterization where Gamma(a, b) has
    mean a/b and variance a/b^2.
    """
    if a_p <= 0 or b_p <= 0 or a_q <= 0 or b_q <= 0:
        return float("inf")

    return (
        (a_p - a_q) * float(psi(a_p))
        - float(gammaln(a_p))
        + float(gammaln(a_q))
        + a_q * (log(b_p) - log(b_q))
        + a_p * (b_q - b_p) / b_p
    )


def check_drift(
    alpha_90d: float,
    beta_90d: float,
    alpha_golden: float,
    beta_golden: float,
    epsilon: float = 0.5,
) -> tuple[bool, float]:
    """Check for distributional drift between 90d and golden posteriors.

    Drift flag fires when:
    1. KL(90d || golden) > epsilon
    2. posterior mean 90d > posterior mean golden

    Drift flags are never auto-resolved and never produce suppression proposals.

    Args:
        alpha_90d, beta_90d: 90d window posterior parameters.
        alpha_golden, beta_golden: Golden snapshot parameters.
        epsilon: KL threshold. Default 0.5 until fleet calibration exists.

    Returns:
        (drift_detected, kl_value)
    """
    kl = gamma_kl(alpha_90d, beta_90d, alpha_golden, beta_golden)

    mean_90d = alpha_90d / beta_90d if beta_90d > 0 else 0.0
    mean_golden = alpha_golden / beta_golden if beta_golden > 0 else 0.0

    drift = kl > epsilon and mean_90d > mean_golden
    return drift, kl
