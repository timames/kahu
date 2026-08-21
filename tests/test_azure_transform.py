"""Tests for Azure/Defender/Entra event transforms — level tables, filtering,
id stability, and the governing invariant (high severity => critical band +
CRITICAL_RULE_IDS membership)."""

from __future__ import annotations

import pytest

from kahu.services.connectors.azure_transform import (
    la_row_id,
    signin_matches_filter,
    transform_defender_alert,
    transform_entra_signin,
    transform_la_row,
)
from kahu.services.triage.filters import (
    CRITICAL_RULE_IDS,
    DeduplicationWindow,
    apply_deterministic_filters,
)


@pytest.fixture(autouse=True)
def _reset_dedup():
    DeduplicationWindow.reset()
    yield
    DeduplicationWindow.reset()


def _defender_alert(severity: str = "high", **extra) -> dict:
    return {
        "id": "da1234",
        "title": "Suspicious PowerShell",
        "severity": severity,
        "category": "Execution",
        "createdDateTime": "2026-08-20T10:00:00Z",
        "incidentId": "77",
        "alertWebUrl": "https://security.microsoft.com/alerts/da1234",
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.userEvidence"},
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "ws01.corp.local",
            },
        ],
        **extra,
    }


def _signin(error_code: int = 0, risk: str = "none", **extra) -> dict:
    return {
        "id": "s-1",
        "createdDateTime": "2026-08-20T10:00:00Z",
        "userPrincipalName": "user@corp.example",
        "ipAddress": "203.0.113.7",
        "appDisplayName": "Office 365",
        "status": {"errorCode": error_code, "failureReason": None},
        "riskLevelDuringSignIn": risk,
        "riskLevelAggregated": "none",
        **extra,
    }


class TestDefenderTransform:
    def test_severity_levels(self):
        expectations = {"informational": 3, "low": 5, "medium": 10, "high": 13}
        for sev, level in expectations.items():
            ev = transform_defender_alert(_defender_alert(sev))
            assert ev["rule"]["level"] == level, sev

    def test_high_is_critical_and_critical_rule(self):
        """Governing invariant: Defender-high can never be auto-dismissed."""
        ev = transform_defender_alert(_defender_alert("high"))
        assert ev["rule"]["id"] == "200104"
        assert ev["rule"]["id"] in CRITICAL_RULE_IDS
        result = apply_deterministic_filters(ev)
        assert result.passed
        assert result.severity == "critical"
        assert result.critical_rule is True

    def test_medium_maps_to_high_band(self):
        ev = transform_defender_alert(_defender_alert("medium"))
        result = apply_deterministic_filters(ev)
        assert result.severity == "high"
        assert result.critical_rule is False

    def test_unknown_severity_falls_back_to_informational(self):
        ev = transform_defender_alert(_defender_alert("bogus"))
        assert ev["rule"]["id"] == "200101"
        assert ev["rule"]["level"] == 3

    def test_agent_from_device_evidence(self):
        ev = transform_defender_alert(_defender_alert())
        assert ev["agent"]["name"] == "ws01.corp.local"

    def test_agent_fallback_without_evidence(self):
        ev = transform_defender_alert(_defender_alert(evidence=[]))
        assert ev["agent"]["name"] == "microsoft-defender"

    def test_id_prefix_and_metadata(self):
        ev = transform_defender_alert(_defender_alert())
        assert ev["id"] == "defender:da1234"
        assert ev["data"]["incident_id"] == "77"
        assert ev["data"]["web_url"].startswith("https://security.microsoft.com")
        assert len(ev["full_log"]) <= 4000


class TestEntraTransform:
    def test_high_risk_is_critical_rule(self):
        ev = transform_entra_signin(_signin(risk="high"))
        assert ev["rule"]["id"] == "200204"
        assert ev["rule"]["id"] in CRITICAL_RULE_IDS
        result = apply_deterministic_filters(ev)
        assert result.severity == "critical"
        assert result.critical_rule is True

    def test_risk_levels(self):
        assert transform_entra_signin(_signin(risk="low"))["rule"]["level"] == 7
        assert transform_entra_signin(_signin(risk="medium"))["rule"]["level"] == 10
        assert transform_entra_signin(_signin(risk="high"))["rule"]["level"] == 13

    def test_failed_signin_gets_auth_group(self):
        """Failed sign-ins must join the existing auth-correlation path."""
        ev = transform_entra_signin(_signin(error_code=50126))
        assert ev["rule"]["id"] == "200201"
        assert ev["rule"]["level"] == 5
        assert "authentication_failed" in ev["rule"]["groups"]
        result = apply_deterministic_filters(ev)
        assert "auth_correlation" in result.rules_fired

    def test_successful_signin_low_level(self):
        ev = transform_entra_signin(_signin())
        assert ev["rule"]["id"] == "200200"
        assert ev["rule"]["level"] == 3
        assert "authentication_failed" not in ev["rule"]["groups"]

    def test_agent_is_upn(self):
        ev = transform_entra_signin(_signin())
        assert ev["agent"]["name"] == "user@corp.example"
        assert ev["id"] == "entra:s-1"


class TestSigninFilter:
    def test_risky_or_failed_default(self):
        assert signin_matches_filter(_signin(risk="low"), "risky_or_failed")
        assert signin_matches_filter(_signin(error_code=50126), "risky_or_failed")
        assert not signin_matches_filter(_signin(), "risky_or_failed")

    def test_risky_only(self):
        assert signin_matches_filter(_signin(risk="high"), "risky_only")
        assert not signin_matches_filter(_signin(error_code=50126), "risky_only")

    def test_failed_only(self):
        assert signin_matches_filter(_signin(error_code=50126), "failed_only")
        assert not signin_matches_filter(_signin(risk="high"), "failed_only")

    def test_all(self):
        assert signin_matches_filter(_signin(), "all")

    def test_aggregated_risk_counts(self):
        s = _signin()
        s["riskLevelAggregated"] = "medium"
        assert signin_matches_filter(s, "risky_only")


class TestLogAnalyticsTransform:
    def test_default_level_used(self):
        ev = transform_la_row({"Computer": "srv1"}, "ws-1", "My query", default_level=10)
        assert ev["rule"]["id"] == "200301"
        assert ev["rule"]["level"] == 10
        assert ev["agent"]["name"] == "srv1"
        assert "My query" in ev["rule"]["description"]

    def test_kahu_level_overrides_and_clamps(self):
        assert transform_la_row({"KahuLevel": 12}, "ws", default_level=5)["rule"]["level"] == 12
        # Clamp: a query can neither suppress (<3) nor exceed the scale (>15)
        assert transform_la_row({"KahuLevel": 1}, "ws", default_level=5)["rule"]["level"] == 3
        assert transform_la_row({"KahuLevel": 99}, "ws", default_level=5)["rule"]["level"] == 15

    def test_invalid_kahu_level_falls_back(self):
        ev = transform_la_row({"KahuLevel": "not-a-number"}, "ws", default_level=7)
        assert ev["rule"]["level"] == 7

    def test_row_id_stable_and_distinct(self):
        row = {"Computer": "srv1", "EventID": 4625, "TimeGenerated": "2026-08-20T10:00:00Z"}
        assert la_row_id("ws-1", dict(row)) == la_row_id("ws-1", dict(row))
        assert la_row_id("ws-1", row) != la_row_id("ws-2", row)
        assert la_row_id("ws-1", row) != la_row_id("ws-1", {**row, "EventID": 4624})
        assert la_row_id("ws-1", row).startswith("la:")
