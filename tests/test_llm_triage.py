"""Tests for Stage 3 — LLM triage prompt building and response parsing."""

import json

from kahu.services.triage.enrichment import EnrichedAlert
from kahu.services.triage.llm_triage import (
    USER_PROMPT_TEMPLATE,
    _build_prompt_data,
    _degraded_result,
    _parse_llm_response,
    canonical_verdict,
)


def _rule_history(history: list) -> dict:
    """Build the aggregate rule-history block the way enrichment.py does.

    ``_build_prompt_data`` reads ``data["rule_history"]`` (a dict of aggregate
    stats + recent_examples), not a raw list. Mirror that shape so the test
    exercises the real contract.
    """
    if not history:
        return {}
    verdict_breakdown: dict[str, int] = {}
    for h in history:
        v = h.get("verdict", "")
        verdict_breakdown[v] = verdict_breakdown.get(v, 0) + 1
    total = len(history)
    fp_count = verdict_breakdown.get("false_positive", 0) + verdict_breakdown.get("acknowledged", 0)
    tp_count = verdict_breakdown.get("true_positive", 0)
    return {
        "total_dispositions": total,
        "verdict_breakdown": verdict_breakdown,
        "false_positive_rate": round(fp_count / total, 2) if total else 0,
        "false_positive_count": fp_count,
        "true_positive_count": tp_count,
        "recent_examples": history,
    }


def _make_enriched(
    rule_id: str = "100",
    level: int = 7,
    description: str = "Test alert",
    agent_name: str = "host1",
    related: list | None = None,
    vuln: dict | None = None,
    history: list | None = None,
) -> EnrichedAlert:
    return EnrichedAlert(
        data={
            "alert": {
                "rule": {
                    "id": rule_id,
                    "level": level,
                    "description": description,
                    "groups": ["test"],
                },
                "agent": {"name": agent_name, "ip": "10.0.0.1"},
                "data": {},
            },
            "asset_context": {"hostname": agent_name, "ip": "10.0.0.1"},
            "related_events": related or [],
            "vuln_state": vuln or {},
            "rule_history": _rule_history(history),
        },
        sources=["alert_data"],
        prompt_hash="abc123",
    )


class TestPromptBuilding:
    def test_includes_rule_info(self):
        enriched = _make_enriched(rule_id="554", description="Exploit attempt")
        prompt = _build_prompt_data(enriched)
        assert "554" in prompt
        assert "Exploit attempt" in prompt

    def test_includes_agent_info(self):
        enriched = _make_enriched(agent_name="webserver01")
        prompt = _build_prompt_data(enriched)
        assert "webserver01" in prompt

    def test_includes_related_events(self):
        related = [
            {"rule": {"id": "100", "level": 5, "description": "Related event"}}
        ]
        enriched = _make_enriched(related=related)
        prompt = _build_prompt_data(enriched)
        assert "Related events" in prompt
        assert "Related event" in prompt

    def test_includes_vuln_state(self):
        vuln = {
            "severity_counts": {"Critical": 2, "High": 5},
            "critical_cves": ["CVE-2024-1234"],
        }
        enriched = _make_enriched(vuln=vuln)
        prompt = _build_prompt_data(enriched)
        assert "CVE-2024-1234" in prompt

    def test_includes_historical_dispositions(self):
        history = [
            {
                "date": "2026-07-01T00:00:00",
                "verdict": "false_positive",
                "analyst": "jdoe",
                "notes": "Known scanner",
            }
        ]
        enriched = _make_enriched(history=history)
        prompt = _build_prompt_data(enriched)
        assert "false_positive" in prompt
        assert "Known scanner" in prompt

    def test_redacts_secrets_in_prompt(self):
        enriched = _make_enriched()
        enriched.data["alert"]["data"] = {"password": "password=hunter2"}
        prompt = _build_prompt_data(enriched)
        assert "hunter2" not in prompt
        assert "REDACTED" in prompt


class TestResponseParsing:
    def test_parses_valid_json(self):
        response = json.dumps({
            "severity": "high",
            "explanation": "Brute force detected",
            "benign_explanations": ["Possible password reset"],
            "recommended_actions": ["Block source IP"],
            "confidence": 0.85,
        })
        result = _parse_llm_response(response)
        assert result["severity"] == "high"
        assert result["confidence"] == 0.85
        assert "Brute force" in result["explanation"]

    def test_strips_markdown_fences(self):
        response = (
            '```json\n{"severity": "medium", "explanation": "test",'
            ' "benign_explanations": [], "recommended_actions": [],'
            ' "confidence": 0.5}\n```'
        )
        result = _parse_llm_response(response)
        assert result["severity"] == "medium"

    def test_rejects_invalid_severity(self):
        response = json.dumps({
            "severity": "SUPER_CRITICAL",
            "explanation": "Bad",
            "benign_explanations": [],
            "recommended_actions": [],
            "confidence": 0.5,
        })
        result = _parse_llm_response(response)
        assert result["severity"] is None

    def test_recovers_json_with_trailing_data(self):
        # Models often emit a valid object then keep talking (or loop). Take the
        # leading object instead of degrading the whole result.
        response = (
            '{"severity": "high", "explanation": "Brute force",'
            ' "benign_explanations": [], "recommended_actions": [],'
            ' "confidence": 0.7}\nHere is some extra commentary the model added.'
        )
        result = _parse_llm_response(response)
        assert result["severity"] == "high"
        assert result.get("parse_error") is not True
        assert result["confidence"] == 0.7

    def test_recovers_json_after_leading_prose(self):
        response = (
            'Sure, here is my assessment:\n'
            '{"severity": "medium", "explanation": "test",'
            ' "benign_explanations": [], "recommended_actions": [],'
            ' "confidence": 0.5}'
        )
        result = _parse_llm_response(response)
        assert result["severity"] == "medium"
        assert result.get("parse_error") is not True

    def test_handles_malformed_json(self):
        result = _parse_llm_response("not json at all")
        assert result["severity"] is None
        assert result.get("parse_error") is True
        # Unparseable output is treated as no model signal, not surfaced raw:
        # the pipeline gates on `degraded`, and the raw text must never reach
        # the UI (it may be a degeneration loop or attacker-controlled content).
        assert result.get("degraded") is True
        assert "not json at all" not in result["explanation"]

    def test_handles_empty_response(self):
        result = _parse_llm_response("")
        assert result["severity"] is None
        assert result.get("parse_error") is True
        assert result.get("degraded") is True


class TestVerdictCanonicalisation:
    """The verdict vocabulary must match DispositionVerdict ("acknowledged").

    Downstream auto-disposition, re-evaluation and the feed API all compare
    against the canonical spelling. A model that emits the bare verb, or an older
    stored payload using the legacy value, must still land on it — otherwise
    every one of those comparisons silently stops matching.
    """

    def test_bare_verb_is_canonicalised(self):
        assert canonical_verdict("acknowledge") == "acknowledged"

    def test_canonical_value_passes_through(self):
        assert canonical_verdict("acknowledged") == "acknowledged"
        assert canonical_verdict("true_positive") == "true_positive"
        assert canonical_verdict("escalate") == "escalate"

    def test_legacy_false_positive_maps_to_acknowledged(self):
        assert canonical_verdict("false_positive") == "acknowledged"

    def test_case_and_whitespace_insensitive(self):
        assert canonical_verdict("  ACKNOWLEDGE ") == "acknowledged"
        assert canonical_verdict("True_Positive") == "true_positive"

    def test_unknown_and_empty_become_none(self):
        assert canonical_verdict("delete_everything") is None
        assert canonical_verdict("") is None
        assert canonical_verdict(None) is None

    def test_parse_canonicalises_model_output(self):
        response = json.dumps({
            "severity": "low",
            "recommended_verdict": "acknowledge",
            "explanation": "Known scanner",
            "benign_explanations": [],
            "recommended_actions": [],
            "confidence": 0.9,
        })
        assert _parse_llm_response(response)["recommended_verdict"] == "acknowledged"

    def test_parse_drops_unrecognised_verdict(self):
        response = json.dumps({
            "severity": "low",
            "recommended_verdict": "ignore_forever",
            "explanation": "x",
            "benign_explanations": [],
            "recommended_actions": [],
            "confidence": 0.9,
        })
        assert _parse_llm_response(response)["recommended_verdict"] is None

    def test_prompt_advertises_the_canonical_spelling(self):
        # The wire protocol we ask the model for and the vocabulary we compare
        # against must not drift apart again.
        assert "acknowledged" in USER_PROMPT_TEMPLATE
        assert "|acknowledge|" not in USER_PROMPT_TEMPLATE


class TestDegradedResult:
    def test_degraded_result_structure(self):
        result = _degraded_result()
        assert result["degraded"] is True
        assert result["severity"] is None
        assert "unavailable" in result["explanation"].lower()
