from kuahene.services.triage.filters import apply_deterministic_filters


def test_suppresses_low_level_alerts():
    alert = {"rule": {"level": 2, "id": "100"}}
    result = apply_deterministic_filters(alert)
    assert not result.passed


def test_passes_mid_level_alerts():
    alert = {"rule": {"level": 7, "id": "200", "description": "test"}}
    result = apply_deterministic_filters(alert)
    assert result.passed
    assert result.severity == "medium"


def test_critical_severity_mapping():
    alert = {"rule": {"level": 14, "id": "300", "description": "critical event"}}
    result = apply_deterministic_filters(alert)
    assert result.passed
    assert result.severity == "critical"
