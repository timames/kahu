"""Risk multiplier computation from configured feature factors."""

from __future__ import annotations

from kahu_tuning.config import RiskConfig


def compute_risk_multiplier(
    geo_risk: str = "low",
    asset_criticality: str = "standard",
    misp_overlap: bool = False,
    protocol_class: str = "",
    config: RiskConfig | None = None,
) -> float:
    """Compute composite risk multiplier r = product of feature factors.

    The suppression threshold is scaled by this multiplier:
    proposals only emitted when posterior_odds >= theta_base * r.
    Higher r means harder to suppress (more evidence needed).
    """
    cfg = config or RiskConfig()

    r = 1.0
    r *= cfg.geo_asn_risk.get(geo_risk, 1.0)
    r *= cfg.asset_criticality.get(asset_criticality, 1.0)

    if misp_overlap:
        r *= cfg.misp_indicator_overlap

    if protocol_class and protocol_class in cfg.protocol_class:
        r *= cfg.protocol_class[protocol_class]

    return r
