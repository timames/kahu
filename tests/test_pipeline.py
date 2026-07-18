"""Tests for the triage pipeline orchestrator — severity bounding logic."""

from kuahene.services.triage.pipeline import _bound_severity


class TestSeverityBounding:
    def test_llm_none_uses_deterministic(self):
        assert _bound_severity("high", None) == "high"

    def test_llm_agrees_with_deterministic(self):
        assert _bound_severity("medium", "medium") == "medium"

    def test_llm_can_raise_severity(self):
        assert _bound_severity("medium", "critical") == "critical"

    def test_llm_can_lower_one_band(self):
        assert _bound_severity("high", "medium") == "medium"

    def test_llm_cannot_lower_two_bands(self):
        # Deterministic says high (3), LLM says low (1), floor is 3-1=2 (medium)
        assert _bound_severity("high", "low") == "medium"

    def test_llm_cannot_suppress_critical(self):
        # Critical (4), LLM says info (0), floor is 4-1=3 (high)
        assert _bound_severity("critical", "info") == "high"

    def test_llm_can_lower_critical_one_band(self):
        assert _bound_severity("critical", "high") == "high"

    def test_llm_cannot_lower_below_info(self):
        # Low (1), LLM says info (0), floor is 1-1=0, so info is allowed
        assert _bound_severity("low", "info") == "info"
