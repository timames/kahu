"""Tests for risk multiplier computation."""

import pytest

from kahu_tuning.config import RiskConfig
from kahu_tuning.risk import compute_risk_multiplier


class TestRiskMultiplier:
    def test_all_defaults_r1(self):
        """Default inputs produce r=1."""
        r = compute_risk_multiplier()
        assert r == pytest.approx(1.0)

    def test_geo_risk_levels(self):
        """Geo/ASN risk multiplies correctly."""
        assert compute_risk_multiplier(geo_risk="low") == pytest.approx(1.0)
        assert compute_risk_multiplier(geo_risk="medium") == pytest.approx(5.0)
        assert compute_risk_multiplier(geo_risk="high") == pytest.approx(25.0)

    def test_asset_criticality(self):
        """Asset criticality multiplies correctly."""
        assert compute_risk_multiplier(asset_criticality="standard") == pytest.approx(1.0)
        assert compute_risk_multiplier(asset_criticality="elevated") == pytest.approx(3.0)
        assert compute_risk_multiplier(asset_criticality="critical") == pytest.approx(10.0)

    def test_misp_overlap(self):
        """MISP indicator overlap adds factor of 50."""
        r = compute_risk_multiplier(misp_overlap=True)
        assert r == pytest.approx(50.0)

    def test_composite_product(self):
        """Factors multiply together."""
        r = compute_risk_multiplier(
            geo_risk="high",       # 25
            asset_criticality="critical",  # 10
            misp_overlap=True,     # 50
        )
        assert r == pytest.approx(25 * 10 * 50)  # 12500

    def test_max_risk_scenario(self):
        """Maximum risk multiplier is geo_high * critical * misp = 12500."""
        r = compute_risk_multiplier(
            geo_risk="high",
            asset_criticality="critical",
            misp_overlap=True,
        )
        assert r == pytest.approx(12500.0)

    def test_custom_protocol_class(self):
        """Protocol class factor from config."""
        config = RiskConfig(protocol_class={"smb": 2.0, "rdp": 3.0})
        r = compute_risk_multiplier(protocol_class="smb", config=config)
        assert r == pytest.approx(2.0)

    def test_unknown_protocol_class_ignored(self):
        """Unknown protocol class has no effect."""
        r = compute_risk_multiplier(protocol_class="unknown")
        assert r == pytest.approx(1.0)
