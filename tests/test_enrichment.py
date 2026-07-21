"""Tests for Stage 2 — Alert enrichment."""

import pytest

from kahu.services.triage.enrichment import (
    EnrichedAlert,
    _extract_asset_context,
    _parse_wazuh_timestamp,
    enrich_alert_group,
)


def _make_alert(agent_name: str = "host1", rule_id: str = "100") -> dict:
    return {
        "rule": {"id": rule_id, "level": 7, "description": "Test"},
        "agent": {
            "name": agent_name,
            "ip": "10.0.0.5",
            "os": {"name": "Ubuntu", "version": "22.04"},
        },
        "data": {},
        "timestamp": "2026-07-18T10:00:00.000+0000",
    }


class TestAssetContext:
    def test_extracts_hostname(self):
        ctx = _extract_asset_context(_make_alert())
        assert ctx["hostname"] == "host1"

    def test_extracts_ip(self):
        ctx = _extract_asset_context(_make_alert())
        assert ctx["ip"] == "10.0.0.5"

    def test_extracts_os(self):
        ctx = _extract_asset_context(_make_alert())
        assert ctx["os"] == "Ubuntu"
        assert ctx["os_version"] == "22.04"

    def test_handles_missing_agent(self):
        ctx = _extract_asset_context({"agent": {}, "data": {}})
        assert ctx == {}


class TestTimestampParsing:
    def test_parses_wazuh_format(self):
        dt = _parse_wazuh_timestamp("2026-07-18T10:00:00.000+0000")
        assert dt.year == 2026
        assert dt.month == 7
        assert dt.hour == 10

    def test_parses_z_suffix(self):
        dt = _parse_wazuh_timestamp("2026-07-18T10:00:00Z")
        assert dt.year == 2026

    def test_raises_on_empty(self):
        with pytest.raises(ValueError):
            _parse_wazuh_timestamp("")


class TestEnrichment:
    @pytest.mark.asyncio
    async def test_enriches_without_dependencies(self):
        """Enrichment works even without DB session or indexer."""
        result = await enrich_alert_group(_make_alert())
        assert isinstance(result, EnrichedAlert)
        assert "alert_data" in result.sources
        assert "asset_context" in result.sources
        assert result.prompt_hash
        assert len(result.prompt_hash) == 16

    @pytest.mark.asyncio
    async def test_redacts_secrets_in_prompt_text(self):
        alert = _make_alert()
        alert["data"] = {"config": "password=secret123"}
        result = await enrich_alert_group(alert)
        assert "secret123" not in result.redacted_prompt_text
        assert "REDACTED" in result.redacted_prompt_text
