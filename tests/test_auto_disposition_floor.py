"""The deterministic floor on auto-dismissal.

These tests exist because the failure they guard is SILENT: an auto-acknowledged
true positive produces exactly what a correctly-dismissed false positive produces
— a closed alert and no one looking. `_bound_severity` makes the LLM's *displayed
severity* respect the ruleset, but auto-disposition is a separate action that can
close an alert on model-derived confidence, and the model reads attacker-
controllable log content inside <ALERT_DATA>. The property under test: a
high/critical DETERMINISTIC finding, or a CRITICAL_RULE_IDS hit, can never be
auto-acknowledged, regardless of tolerance, model confidence, or rule history.

Written as an independent (adversarial) corpus, not by the mechanism's author:
each case is a way an attacker or a numb history could talk the system into
silence, and the assertion is that it can't.

No new dependencies beyond the project's dev set (pytest, pytest-asyncio) plus
aiosqlite for the in-memory integration cases.
"""

from __future__ import annotations

import inspect

# aiosqlite is a declared dev dependency and these cases must FAIL, not skip, if
# it is missing — a silently skipped security regression test is the same as no
# test at all.
import aiosqlite  # noqa: F401
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import kahu.models  # noqa: F401  — register every table on Base.metadata
from kahu.models.alerts import Alert, Severity
from kahu.models.base import Base
from kahu.services.triage.auto_disposition import (
    NON_DISMISSIBLE_SEVERITIES,
    _infer_verdict,
    auto_dismiss_forbidden,
    maybe_auto_dispose,
)
from kahu.services.triage.filters import apply_deterministic_filters
from kahu.services.triage.pipeline import _bound_severity


# --------------------------------------------------------------------------
# Pure predicate — the security-critical decision, tested the way the repo
# already tests _bound_severity (test_pipeline.py): no DB, just the function.
# --------------------------------------------------------------------------
class TestAutoDismissForbidden:
    def test_critical_severity_forbidden(self):
        assert auto_dismiss_forbidden("critical") is True

    def test_high_severity_forbidden(self):
        assert auto_dismiss_forbidden("high") is True

    def test_medium_low_info_allowed(self):
        assert auto_dismiss_forbidden("medium") is False
        assert auto_dismiss_forbidden("low") is False
        assert auto_dismiss_forbidden("info") is False

    def test_none_or_unknown_is_not_forbidden_by_severity_alone(self):
        # Unknown severity does not by itself forbid dismissal (the pipeline
        # always supplies a real deterministic severity); the critical-rule
        # flag is the belt to this suspenders.
        assert auto_dismiss_forbidden(None) is False
        assert auto_dismiss_forbidden("") is False

    def test_case_and_whitespace_insensitive(self):
        assert auto_dismiss_forbidden("  CRITICAL ") is True
        assert auto_dismiss_forbidden("High") is True

    def test_critical_rule_flag_forbids_regardless_of_severity(self):
        # A CRITICAL_RULE_IDS hit is forbidden even if its mapped severity were
        # somehow low. The flag is the deterministic "never suppress" signal.
        assert auto_dismiss_forbidden("low", critical_rule=True) is True
        assert auto_dismiss_forbidden(None, critical_rule=True) is True

    def test_severity_set_is_exactly_high_and_critical(self):
        assert frozenset({"critical", "high"}) == NON_DISMISSIBLE_SEVERITIES


# --------------------------------------------------------------------------
# History poisoning path (finding 9 / the "numb key" recurring bug).
# _infer_verdict is a RECOMMENDER: it will still say "acknowledged" on a poisoned
# rule-FP history, which is exactly why enforcement cannot live here. The gate in
# maybe_auto_dispose refuses to act on it (see integration tests below).
# --------------------------------------------------------------------------
class TestInferVerdictIsRecommenderNotEnforcer:
    def test_poisoned_history_still_recommends_dismiss(self):
        # A rule made noisy enough (fp_rate 0.7) recommends dismissal even for a
        # serious-looking instance. This is the numb-key hazard the gate stops.
        assert _infer_verdict(0.5, [], "critical", "critical", rule_fp_rate=0.7) == "acknowledged"

    def test_high_confidence_still_recommends_true_positive(self):
        assert _infer_verdict(0.95, [], "critical", "critical", rule_fp_rate=0.0) == "true_positive"


# --------------------------------------------------------------------------
# Laundering interaction: the model drops a deterministic critical one band to
# "high" via _bound_severity. The floor keys on the DETERMINISTIC value, so the
# laundered result is still forbidden.
# --------------------------------------------------------------------------
class TestLaunderingInteraction:
    def test_bound_severity_launders_critical_to_high(self):
        assert _bound_severity("critical", "info") == "high"  # one band, as designed

    def test_floor_uses_deterministic_not_bounded(self):
        deterministic = "critical"
        bounded = _bound_severity(deterministic, "low")  # -> "high"
        assert bounded == "high"
        # Auto-dismiss decision must key on the deterministic value, so both the
        # pre- and post-laundering severities are forbidden.
        assert auto_dismiss_forbidden(deterministic) is True
        assert auto_dismiss_forbidden(bounded) is True


# --------------------------------------------------------------------------
# Wiring contract: maybe_auto_dispose must accept the deterministic inputs.
# --------------------------------------------------------------------------
def test_maybe_auto_dispose_accepts_deterministic_floor_params():
    sig = inspect.signature(maybe_auto_dispose)
    assert "deterministic_severity" in sig.parameters
    assert "critical_rule" in sig.parameters
    # keyword-only, safe defaults so existing callers are unaffected
    assert sig.parameters["deterministic_severity"].kind is inspect.Parameter.KEYWORD_ONLY
    assert sig.parameters["critical_rule"].default is False


def test_critical_rule_flows_from_filters():
    # A CRITICAL_RULE_IDS alert carries the flag the floor reads downstream.
    res = apply_deterministic_filters({
        "rule": {"id": "554", "level": 3, "description": "exploit", "groups": []},
        "agent": {"name": "h1"},
    })
    assert res.passed
    assert res.critical_rule is True
    # An ordinary rule does not.
    res2 = apply_deterministic_filters({
        "rule": {"id": "12345", "level": 7, "description": "misc", "groups": []},
        "agent": {"name": "h1"},
    })
    assert res2.critical_rule is False


# --------------------------------------------------------------------------
# Integration: real maybe_auto_dispose over an in-memory DB. This is the
# suppression-injection arm — an alert whose model output screams "benign,
# dismiss" must NOT close when the deterministic finding is critical.
# --------------------------------------------------------------------------
async def _make_session():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


# The injected model verdict: attacker-controllable content persuaded the model
# the alert is benign with high dismiss confidence.
_BENIGN_LLM = {
    "severity": "info",
    "recommended_verdict": None,          # inferred path
    "benign_explanations": ["scheduled maintenance", "known scanner"],
    "confidence": 0.15,                   # low threat -> high FP confidence
    "degraded": False,
}


async def _insert_alert(session, severity: Severity, rule_id: str = "999") -> Alert:
    alert = Alert(
        wazuh_alert_id="w-1",
        rule_id=rule_id,
        rule_description="test",
        severity=severity,
        agent_name="host1",
        raw_event={"rule": {"id": rule_id}},
    )
    session.add(alert)
    await session.flush()
    return alert


async def test_critical_deterministic_is_not_auto_dismissed():
    session_factory = await _make_session()
    async with session_factory() as session:
        # Bounded/displayed severity laundered to HIGH; deterministic is CRITICAL.
        alert = await _insert_alert(session, Severity.HIGH)
        result = await maybe_auto_dispose(
            alert, _BENIGN_LLM, session,
            deterministic_severity="critical",
            critical_rule=False,
        )
    assert result.auto_handled is False
    assert result.floor_blocked_dismiss is True


async def test_critical_rule_flag_blocks_dismiss():
    session_factory = await _make_session()
    async with session_factory() as session:
        alert = await _insert_alert(session, Severity.MEDIUM, rule_id="554")
        result = await maybe_auto_dispose(
            alert, _BENIGN_LLM, session,
            deterministic_severity="medium",
            critical_rule=True,
        )
    assert result.auto_handled is False
    assert result.floor_blocked_dismiss is True


# The model recommending dismissal OUTRIGHT, rather than it being inferred. This
# path only became reachable once the verdict spelling was canonicalised
# ("acknowledge" -> "acknowledged"); before that the comparison never matched and
# an explicit recommendation was silently ignored. It is the most direct
# injection route — attacker-controlled log text talking the model into naming
# the dismissal itself — so the floor has to hold here too.
_EXPLICIT_DISMISS_LLM = {
    "severity": "info",
    "recommended_verdict": "acknowledged",
    "benign_explanations": ["routine backup job"],
    "confidence": 0.99,                   # far above every tolerance threshold
    "degraded": False,
}


async def test_explicit_model_dismissal_is_blocked_on_critical():
    session_factory = await _make_session()
    async with session_factory() as session:
        alert = await _insert_alert(session, Severity.HIGH)
        result = await maybe_auto_dispose(
            alert, _EXPLICIT_DISMISS_LLM, session,
            deterministic_severity="critical",
            critical_rule=False,
        )
    assert result.auto_handled is False
    assert result.floor_blocked_dismiss is True


async def test_explicit_model_dismissal_is_blocked_on_critical_rule():
    session_factory = await _make_session()
    async with session_factory() as session:
        alert = await _insert_alert(session, Severity.LOW, rule_id="554")
        result = await maybe_auto_dispose(
            alert, _EXPLICIT_DISMISS_LLM, session,
            deterministic_severity="low",
            critical_rule=True,
        )
    assert result.auto_handled is False
    assert result.floor_blocked_dismiss is True


async def test_explicit_model_dismissal_works_on_low_severity():
    # The path is genuinely live — it closes an ordinary noise alert.
    session_factory = await _make_session()
    async with session_factory() as session:
        alert = await _insert_alert(session, Severity.LOW)
        result = await maybe_auto_dispose(
            alert, _EXPLICIT_DISMISS_LLM, session,
            deterministic_severity="low",
            critical_rule=False,
        )
    assert result.auto_handled is True
    assert result.verdict == "acknowledged"


async def test_legacy_verdict_spelling_is_honoured():
    # Payloads stored before canonicalisation used the bare verb. They must
    # behave identically — including being blocked by the floor.
    legacy = dict(_EXPLICIT_DISMISS_LLM, recommended_verdict="acknowledge")
    session_factory = await _make_session()
    async with session_factory() as session:
        blocked = await _insert_alert(session, Severity.HIGH)
        blocked_result = await maybe_auto_dispose(
            blocked, legacy, session,
            deterministic_severity="critical",
            critical_rule=False,
        )
        allowed = await _insert_alert(session, Severity.LOW, rule_id="1001")
        allowed_result = await maybe_auto_dispose(
            allowed, legacy, session,
            deterministic_severity="low",
            critical_rule=False,
        )
    assert blocked_result.floor_blocked_dismiss is True
    assert allowed_result.auto_handled is True


async def test_low_deterministic_still_auto_dismisses():
    # Contrast case: the exact same benign model output DOES auto-close a genuine
    # low-severity noise alert. The floor is a scalpel, not a blanket off-switch.
    session_factory = await _make_session()
    async with session_factory() as session:
        alert = await _insert_alert(session, Severity.LOW)
        result = await maybe_auto_dispose(
            alert, _BENIGN_LLM, session,
            deterministic_severity="low",
            critical_rule=False,
        )
    assert result.auto_handled is True
    assert result.verdict == "acknowledged"
    assert result.floor_blocked_dismiss is False
