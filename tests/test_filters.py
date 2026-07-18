"""Tests for Stage 1 — Deterministic filtering."""

from kuahene.services.triage.filters import (
    DeduplicationWindow,
    apply_deterministic_filters,
)


def _make_alert(rule_id: str = "200", level: int = 7, agent: str = "host1", groups: list | None = None) -> dict:
    return {
        "rule": {
            "id": rule_id,
            "level": level,
            "description": f"Test rule {rule_id}",
            "groups": groups or [],
        },
        "agent": {"name": agent, "ip": "10.0.0.1"},
        "timestamp": "2026-07-18T10:00:00.000+0000",
    }


class TestLevelSuppression:
    def setup_method(self):
        DeduplicationWindow.reset()

    def test_suppresses_low_level_alerts(self):
        result = apply_deterministic_filters(_make_alert(level=2))
        assert not result.passed
        assert "level_suppression" in result.rules_fired

    def test_passes_mid_level_alerts(self):
        result = apply_deterministic_filters(_make_alert(level=7))
        assert result.passed
        assert result.severity == "medium"

    def test_critical_severity_mapping(self):
        result = apply_deterministic_filters(_make_alert(level=14))
        assert result.passed
        assert result.severity == "critical"

    def test_high_severity_mapping(self):
        result = apply_deterministic_filters(_make_alert(level=10))
        assert result.passed
        assert result.severity == "high"

    def test_low_severity_mapping(self):
        result = apply_deterministic_filters(_make_alert(level=4))
        assert result.passed
        assert result.severity == "low"


class TestSuppressedRules:
    def setup_method(self):
        DeduplicationWindow.reset()

    def test_suppresses_known_noisy_rules(self):
        result = apply_deterministic_filters(_make_alert(rule_id="86001", level=5))
        assert not result.passed
        assert "suppressed:86001" in result.rules_fired

    def test_custom_suppression_set(self):
        result = apply_deterministic_filters(
            _make_alert(rule_id="999", level=5),
            suppressed_rules={"999"},
        )
        assert not result.passed

    def test_does_not_suppress_unlisted_rules(self):
        result = apply_deterministic_filters(_make_alert(rule_id="12345", level=5))
        assert result.passed


class TestCriticalRules:
    def setup_method(self):
        DeduplicationWindow.reset()

    def test_critical_rules_always_pass(self):
        # Critical rule at low level still passes and gets elevated
        result = apply_deterministic_filters(_make_alert(rule_id="554", level=3))
        assert result.passed
        assert result.severity == "critical"
        assert "critical_rule_pass" in result.rules_fired

    def test_critical_rules_bypass_suppression(self):
        # Even if in suppression set, critical rules pass
        result = apply_deterministic_filters(
            _make_alert(rule_id="554", level=5),
            suppressed_rules={"554"},
        )
        assert result.passed


class TestDeduplication:
    def setup_method(self):
        DeduplicationWindow.reset()

    def test_first_occurrence_passes(self):
        result = apply_deterministic_filters(_make_alert(rule_id="500", level=5))
        assert result.passed

    def test_duplicate_within_window_suppressed(self):
        apply_deterministic_filters(_make_alert(rule_id="500", level=5, agent="host1"))
        result = apply_deterministic_filters(_make_alert(rule_id="500", level=5, agent="host1"))
        assert not result.passed
        assert "dedup_suppressed" in result.rules_fired

    def test_same_rule_different_agent_passes(self):
        apply_deterministic_filters(_make_alert(rule_id="500", level=5, agent="host1"))
        result = apply_deterministic_filters(_make_alert(rule_id="500", level=5, agent="host2"))
        assert result.passed

    def test_high_level_alerts_skip_dedup(self):
        apply_deterministic_filters(_make_alert(rule_id="600", level=12, agent="host1"))
        result = apply_deterministic_filters(_make_alert(rule_id="600", level=12, agent="host1"))
        # Level >= 10 skips dedup
        assert result.passed


class TestCorrelation:
    def setup_method(self):
        DeduplicationWindow.reset()

    def test_auth_event_tagged(self):
        result = apply_deterministic_filters(
            _make_alert(groups=["authentication_failed", "sshd"], level=7)
        )
        assert result.passed
        assert "auth_correlation" in result.rules_fired

    def test_fim_event_tagged(self):
        result = apply_deterministic_filters(
            _make_alert(groups=["syscheck", "fim"], level=7)
        )
        assert result.passed
        assert "fim_correlation" in result.rules_fired

    def test_correlation_key_generated(self):
        result = apply_deterministic_filters(_make_alert(level=7))
        assert result.correlation_key is not None
        assert len(result.correlation_key) == 12
