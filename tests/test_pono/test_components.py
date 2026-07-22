"""Tests for individual Pono Score component scorers."""

from __future__ import annotations

import pytest

from kahu_pono.components.detection import DetectionInput, score_detection
from kahu_pono.components.tuning import TuningInput, score_tuning
from kahu_pono.components.vulnerability import VulnerabilityInput, score_vulnerability
from kahu_pono.components.identity import IdentityInput, score_identity
from kahu_pono.components.response import ResponseInput, score_response
from kahu_pono.components.human import HumanInput, score_human


# --- Detection ---

class TestDetection:
    WEIGHTS = {
        "update_freshness": 0.25,
        "content_age": 0.20,
        "canary_pass_rate": 0.20,
        "sensor_health": 0.20,
        "log_source_coverage": 0.15,
    }

    def test_perfect_detection(self):
        inp = DetectionInput(
            last_update_days=1,
            content_age_days=10,
            canary_total=10, canary_passed=10,
            sensors_total=50, sensors_healthy=50,
            expected_sources=20, active_sources=20,
        )
        raw, details = score_detection(inp, self.WEIGHTS)
        assert raw > 0.9

    def test_not_assessed(self):
        inp = DetectionInput(data_available=False)
        raw, details = score_detection(inp, self.WEIGHTS)
        assert raw == 0.0
        assert details["status"] == "not assessed"

    def test_stale_detection_penalized(self):
        fresh = DetectionInput(last_update_days=1, sensors_total=10, sensors_healthy=10)
        stale = DetectionInput(last_update_days=20, sensors_total=10, sensors_healthy=10)
        raw_fresh, _ = score_detection(fresh, self.WEIGHTS)
        raw_stale, _ = score_detection(stale, self.WEIGHTS)
        assert raw_fresh > raw_stale

    def test_no_sensors_scores_zero_health(self):
        inp = DetectionInput(sensors_total=0, sensors_healthy=0)
        _, details = score_detection(inp, self.WEIGHTS)
        assert details["sensor_health"] == 0.0


# --- Tuning ---

class TestTuning:
    WEIGHTS = {
        "active_suppression_count": 0.25,
        "mean_tune_age": 0.25,
        "expired_unreviewed": 0.25,
        "drift_flags_unacked": 0.25,
    }

    def test_perfect_tuning(self):
        inp = TuningInput(
            active_suppressions=10, expected_suppressions=10,
            mean_tune_age_days=30,
            total_proposals=50, expired_unreviewed=0,
            drift_flags_total=5, drift_flags_unacked=0,
        )
        raw, _ = score_tuning(inp, self.WEIGHTS)
        assert raw == 1.0

    def test_all_expired(self):
        inp = TuningInput(total_proposals=10, expired_unreviewed=10)
        _, details = score_tuning(inp, self.WEIGHTS)
        assert details["expired_unreviewed"] == 0.0

    def test_not_assessed(self):
        inp = TuningInput(data_available=False)
        raw, details = score_tuning(inp, self.WEIGHTS)
        assert raw == 0.0


# --- Vulnerability ---

class TestVulnerability:
    WEIGHTS = {"findings_weighted": 0.50, "remediation_velocity": 0.50}

    def test_no_vulns_perfect(self):
        inp = VulnerabilityInput(critical_high_total=0, remediation_total=0)
        raw, _ = score_vulnerability(inp, self.WEIGHTS)
        assert raw == 1.0

    def test_all_open_scores_low(self):
        inp = VulnerabilityInput(
            critical_high_open=100, critical_high_total=100,
            remediated_in_sla=0, remediation_total=100,
        )
        raw, _ = score_vulnerability(inp, self.WEIGHTS)
        assert raw == 0.0

    def test_scanner_disabled_not_assessed(self):
        inp = VulnerabilityInput(data_available=False)
        raw, details = score_vulnerability(inp, self.WEIGHTS)
        assert raw == 0.0
        assert details["status"] == "not assessed"


# --- Identity ---

class TestIdentity:
    WEIGHTS = {"mfa_coverage": 0.30, "stale_accounts": 0.25, "admin_count": 0.25, "secret_age": 0.20}

    def test_full_mfa(self):
        inp = IdentityInput(
            accounts_with_mfa=100, accounts_total=100,
            stale_accounts=0,
            privileged_accounts=5, expected_privileged=5,
            secrets_rotated=10, secrets_total=10,
        )
        raw, _ = score_identity(inp, self.WEIGHTS)
        assert raw == 1.0

    def test_no_mfa(self):
        inp = IdentityInput(accounts_with_mfa=0, accounts_total=100)
        _, details = score_identity(inp, self.WEIGHTS)
        assert details["mfa_coverage"] == 0.0


# --- Response ---

class TestResponse:
    WEIGHTS = {"median_ack_time": 0.35, "cases_past_sla": 0.35, "playbook_success_rate": 0.30}

    def test_perfect_response(self):
        inp = ResponseInput(
            median_ack_minutes=5,
            cases_in_sla=100, cases_total=100,
            playbook_successes=50, playbook_executions=50,
        )
        raw, _ = score_response(inp, self.WEIGHTS)
        assert raw == 1.0

    def test_slow_ack_penalized(self):
        fast = ResponseInput(median_ack_minutes=5)
        slow = ResponseInput(median_ack_minutes=40)
        raw_fast, _ = score_response(fast, self.WEIGHTS)
        raw_slow, _ = score_response(slow, self.WEIGHTS)
        assert raw_fast > raw_slow


# --- Human ---

class TestHuman:
    WEIGHTS = {"training_completion": 0.50, "training_recency": 0.50}

    def test_fully_trained(self):
        inp = HumanInput(staff_trained=50, staff_total=50, mean_training_age_days=30)
        raw, _ = score_human(inp, self.WEIGHTS)
        assert raw > 0.9

    def test_no_training(self):
        inp = HumanInput(staff_trained=0, staff_total=50, mean_training_age_days=400)
        raw, _ = score_human(inp, self.WEIGHTS)
        assert raw == 0.0
