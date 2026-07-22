"""Tests for Pono Score engine -- acceptance tests for Phase 3."""

from __future__ import annotations

import pytest

from kahu_pono.config import WeightsSchema
from kahu_pono.engine import (
    check_pono_drop,
    compute_pono_score,
    find_biggest_gain,
    score_component,
)
from kahu_pono.components.detection import DetectionInput
from kahu_pono.components.tuning import TuningInput
from kahu_pono.components.vulnerability import VulnerabilityInput
from kahu_pono.components.identity import IdentityInput
from kahu_pono.components.response import ResponseInput
from kahu_pono.components.human import HumanInput
from kahu_pono.freshness import freshness_factor


def _load_schema() -> WeightsSchema:
    from pathlib import Path
    schema_path = Path(__file__).resolve().parents[2] / "config" / "weights_schema.json"
    return WeightsSchema.from_file(schema_path)


def _perfect_inputs() -> dict:
    """All components with perfect scores."""
    return {
        "detection_posture": DetectionInput(
            last_update_days=1, content_age_days=5,
            canary_total=10, canary_passed=10,
            sensors_total=50, sensors_healthy=50,
            expected_sources=20, active_sources=20,
        ),
        "tuning_hygiene": TuningInput(
            active_suppressions=10, expected_suppressions=10,
            mean_tune_age_days=30,
            total_proposals=50, expired_unreviewed=0,
            drift_flags_total=5, drift_flags_unacked=0,
        ),
        "vulnerability_posture": VulnerabilityInput(
            critical_high_total=0,
            remediation_total=0,
        ),
        "identity_access": IdentityInput(
            accounts_with_mfa=100, accounts_total=100,
            stale_accounts=0,
            privileged_accounts=5, expected_privileged=5,
            secrets_rotated=10, secrets_total=10,
        ),
        "response_readiness": ResponseInput(
            median_ack_minutes=5,
            cases_in_sla=100, cases_total=100,
            playbook_successes=50, playbook_executions=50,
        ),
        "human_layer": HumanInput(
            staff_trained=50, staff_total=50,
            mean_training_age_days=30,
        ),
    }


class TestFixtureScores:
    """AT-P3-1: Known fixture → known score."""

    def test_perfect_inputs_near_100(self):
        schema = _load_schema()
        result = compute_pono_score(schema, _perfect_inputs())
        # All components perfect with age=0: should be very close to 100
        assert result.pono_score > 95.0
        assert result.pono_score <= 100.0

    def test_all_components_assessed(self):
        schema = _load_schema()
        result = compute_pono_score(schema, _perfect_inputs())
        for c in result.components:
            assert c.assessed is True
            assert c.label == "assessed"

    def test_total_weight_is_100(self):
        schema = _load_schema()
        assert schema.total_weight() == 100

    def test_empty_inputs_all_not_assessed(self):
        schema = _load_schema()
        result = compute_pono_score(schema, {})
        for c in result.components:
            assert c.assessed is False
            assert c.label == "not assessed"
        # Each component gets ceiling (40% of max)
        expected = sum(cw.weight * 0.40 for cw in schema.components.values())
        assert abs(result.pono_score - expected) < 0.01


class TestScannerDisabledCeiling:
    """AT-P3-2: Scanner disabled → vulnerability_posture capped at ceiling."""

    def test_scanner_disabled_caps_at_ceiling(self):
        schema = _load_schema()
        inputs = _perfect_inputs()
        # Disable scanner
        inputs["vulnerability_posture"] = VulnerabilityInput(data_available=False)
        result = compute_pono_score(schema, inputs)

        vuln_component = next(c for c in result.components if c.name == "vulnerability_posture")
        assert vuln_component.assessed is False
        # Should be capped at 40% of 20 = 8.0
        assert vuln_component.weighted_score == pytest.approx(8.0)
        assert vuln_component.max_points == 20

    def test_scanner_disabled_total_score_reduced(self):
        schema = _load_schema()
        perfect = compute_pono_score(schema, _perfect_inputs())
        inputs = _perfect_inputs()
        inputs["vulnerability_posture"] = VulnerabilityInput(data_available=False)
        disabled = compute_pono_score(schema, inputs)
        assert disabled.pono_score < perfect.pono_score


class TestFreshnessDecay:
    """AT-P3-3: Freshness decay visible on component score."""

    def test_fresh_evidence_scores_higher(self):
        schema = _load_schema()
        inputs = _perfect_inputs()

        fresh = compute_pono_score(schema, inputs, evidence_ages={})
        aged = compute_pono_score(
            schema, inputs,
            evidence_ages={name: 30.0 for name in schema.components},
        )
        assert fresh.pono_score > aged.pono_score

    def test_90_day_old_evidence_significant_decay(self):
        schema = _load_schema()
        inputs = _perfect_inputs()
        aged = compute_pono_score(
            schema, inputs,
            evidence_ages={name: 90.0 for name in schema.components},
        )
        # At delta=0.992, 90 days => factor ~0.486
        # Perfect raw ~1.0 * 0.486 * total_weight
        expected_factor = freshness_factor(90.0, schema.freshness_decay_delta)
        assert expected_factor < 0.5
        # Score should be roughly half
        assert aged.pono_score < 55.0

    def test_zero_age_no_decay(self):
        schema = _load_schema()
        inputs = _perfect_inputs()
        result = compute_pono_score(
            schema, inputs,
            evidence_ages={name: 0.0 for name in schema.components},
        )
        no_ages = compute_pono_score(schema, inputs)
        assert abs(result.pono_score - no_ages.pono_score) < 0.01


class TestBiggestGain:
    """AT-P3-4: Biggest-gain matches brute-force search."""

    def test_biggest_gain_is_weakest_component(self):
        schema = _load_schema()
        inputs = _perfect_inputs()
        # Make vulnerability very weak
        inputs["vulnerability_posture"] = VulnerabilityInput(
            critical_high_open=90, critical_high_total=100,
            remediated_in_sla=10, remediation_total=100,
        )
        result = compute_pono_score(schema, inputs)
        assert result.biggest_gain is not None
        assert result.biggest_gain["component"] == "vulnerability_posture"

    def test_biggest_gain_matches_brute_force(self):
        schema = _load_schema()
        inputs = _perfect_inputs()
        # Weaken two components
        inputs["vulnerability_posture"] = VulnerabilityInput(
            critical_high_open=50, critical_high_total=100,
            remediated_in_sla=50, remediation_total=100,
        )
        inputs["human_layer"] = HumanInput(
            staff_trained=10, staff_total=50,
            mean_training_age_days=200,
        )
        result = compute_pono_score(schema, inputs)

        # Brute force: find component with max gap
        max_gap = -1.0
        max_name = None
        for c in result.components:
            gap = c.max_points - c.weighted_score
            if gap > max_gap:
                max_gap = gap
                max_name = c.name

        assert result.biggest_gain is not None
        assert result.biggest_gain["component"] == max_name
        assert result.biggest_gain["available_gain"] == pytest.approx(max_gap, abs=0.01)

    def test_perfect_score_minimal_gain(self):
        schema = _load_schema()
        result = compute_pono_score(schema, _perfect_inputs())
        if result.biggest_gain is not None:
            assert result.biggest_gain["available_gain"] < 5.0


class TestPonoDrop:
    """Pono drop event detection."""

    def test_drop_detected(self):
        drop = check_pono_drop(current=70.0, previous=80.0, threshold=5)
        assert drop is not None
        assert drop["event"] == "pono_drop"
        assert drop["drop"] == 10.0

    def test_no_drop(self):
        drop = check_pono_drop(current=78.0, previous=80.0, threshold=5)
        assert drop is None

    def test_exact_threshold(self):
        drop = check_pono_drop(current=75.0, previous=80.0, threshold=5)
        assert drop is not None


class TestFreshnessModule:
    """Tests for freshness.py functions."""

    def test_freshness_factor_at_zero(self):
        assert freshness_factor(0.0) == 1.0

    def test_freshness_factor_decreases(self):
        f7 = freshness_factor(7.0)
        f30 = freshness_factor(30.0)
        f90 = freshness_factor(90.0)
        assert 1.0 > f7 > f30 > f90 > 0.0

    def test_freshness_negative_age(self):
        assert freshness_factor(-5.0) == 1.0
