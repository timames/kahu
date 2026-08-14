"""Tests for the compliance engine — controls mapping, coverage, gap analysis."""

from __future__ import annotations

from kahu.services.compliance.controls import tags_for_alert

# ---------------------------------------------------------------------------
# Control-tag mapping
# ---------------------------------------------------------------------------

def test_tags_for_alert_auth_success():
    alert = {"rule": {"groups": ["authentication_success", "syslog"]}}
    tags = tags_for_alert(alert)
    assert "800-171:3.1.1" in tags
    assert "800-171:3.5.1" in tags
    assert "800-171:3.3.1" in tags  # from syslog


def test_tags_for_alert_firewall():
    alert = {"rule": {"groups": ["firewall"]}}
    tags = tags_for_alert(alert)
    assert "800-171:3.13.1" in tags
    assert "CIS:13.1" in tags
    assert "SOC2:CC6.6" in tags


def test_tags_for_alert_malware():
    alert = {"rule": {"groups": ["virus", "rootcheck"]}}
    tags = tags_for_alert(alert)
    assert "800-171:3.14.2" in tags
    assert "CIS:10.1" in tags
    assert "SOC2:CC6.8" in tags


def test_tags_for_alert_empty_groups():
    alert = {"rule": {"groups": []}}
    assert tags_for_alert(alert) == []


def test_tags_for_alert_no_rule():
    alert = {}
    assert tags_for_alert(alert) == []


def test_tags_for_alert_unknown_group():
    alert = {"rule": {"groups": ["custom_unknown_group"]}}
    assert tags_for_alert(alert) == []


def test_tags_for_alert_case_insensitive():
    alert = {"rule": {"groups": ["Authentication_Success"]}}
    tags = tags_for_alert(alert)
    assert "800-171:3.1.1" in tags


def test_tags_for_alert_deduplication():
    """Multiple groups mapping to the same control should not produce duplicates."""
    alert = {"rule": {"groups": ["authentication_success", "authentication_failed"]}}
    tags = tags_for_alert(alert)
    assert tags == sorted(set(tags))


def test_tags_for_alert_sorted():
    alert = {"rule": {"groups": ["firewall", "audit"]}}
    tags = tags_for_alert(alert)
    assert tags == sorted(tags)


# ---------------------------------------------------------------------------
# Engine data structures (import smoke test)
# ---------------------------------------------------------------------------

def test_engine_imports():
    from kahu.services.compliance.engine import (
        KAHU_CAPABILITIES,
        MANUAL_RECOMMENDATIONS,
        ControlStatus,
        CoverageReport,
    )
    assert len(KAHU_CAPABILITIES) > 0
    assert len(MANUAL_RECOMMENDATIONS) > 0
    assert ControlStatus is not None
    assert CoverageReport is not None


def test_evidence_service_imports():
    from kahu.services.compliance.evidence import (
        GENESIS_HASH,
        record_evidence,
        verify_chain,
    )
    assert GENESIS_HASH == "0" * 64
    assert callable(record_evidence)
    assert callable(verify_chain)


# ---------------------------------------------------------------------------
# Engine helper: _recommendation_for
# ---------------------------------------------------------------------------

def test_recommendation_for_manual_tag():
    from kahu.services.compliance.engine import _recommendation_for

    rec = _recommendation_for(["mfa"])
    assert "multi-factor" in rec.lower()


def test_recommendation_for_kahu_capability():
    from kahu.services.compliance.engine import _recommendation_for

    rec = _recommendation_for(["audit_logging"])
    assert "connect" in rec.lower() or "collects" in rec.lower() or "activate" in rec.lower()


def test_recommendation_for_unknown_tag():
    from kahu.services.compliance.engine import _recommendation_for

    rec = _recommendation_for(["totally_unknown_tag"])
    assert "compensating" in rec.lower()
