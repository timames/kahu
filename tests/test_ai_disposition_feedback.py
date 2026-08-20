"""AI dispositions must never re-enter the AI's own evidence base.

The failure this guards was observed live: kahu-ai auto-confirmed a noisy rule
often enough that the recent-100 disposition window fed to enrichment became
100% kahu-ai true_positives. Every subsequent triage of that rule was then told
"100% true-positive history — treat with elevated seriousness", so the model
confirmed again — a self-reinforcing loop with zero human input. The mirror
image is worse: auto-ACKNOWLEDGEMENTS feed _get_rule_fp_rate, which raises the
noisy-OR dismiss confidence, so each auto-dismiss makes the next more likely —
a compounding slide toward silence.

Property under test: every disposition statistic that feeds back into triage
(rule history and agent history in enrichment, rule FP rate in
auto_disposition) counts HUMAN verdicts only. kahu-ai's records stay in the DB
(audit trail) but are never signal.
"""

from __future__ import annotations

# aiosqlite is a declared dev dependency and these cases must FAIL, not skip,
# if it is missing — a silently skipped security regression test is the same as
# no test at all.
import aiosqlite  # noqa: F401
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import kahu.models  # noqa: F401  — register every table on Base.metadata
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.base import Base
from kahu.services.triage.auto_disposition import _get_rule_fp_rate
from kahu.services.triage.disposition import AI_ANALYST
from kahu.services.triage.enrichment import (
    _fetch_agent_history,
    _fetch_historical_dispositions,
)


async def _make_session():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


async def _insert_disposed_alert(
    session,
    rule_id: str,
    verdict: DispositionVerdict,
    analyst: str,
    agent_name: str = "host1",
) -> None:
    alert = Alert(
        wazuh_alert_id=f"w-{rule_id}-{analyst}-{id(object())}",
        rule_id=rule_id,
        rule_description="test",
        severity=Severity.MEDIUM,
        agent_name=agent_name,
        raw_event={"rule": {"id": rule_id}},
    )
    session.add(alert)
    await session.flush()
    session.add(
        AlertDisposition(
            alert_id=alert.id,
            verdict=verdict,
            analyst=analyst,
        )
    )
    await session.flush()


async def test_rule_history_excludes_ai_dispositions():
    # The live incident, in miniature: the recent window is dominated by
    # kahu-ai auto-confirms; the only human input is acknowledgements.
    session_factory = await _make_session()
    async with session_factory() as session:
        for _ in range(20):
            await _insert_disposed_alert(
                session, "60107", DispositionVerdict.TRUE_POSITIVE, AI_ANALYST
            )
        for _ in range(4):
            await _insert_disposed_alert(
                session, "60107", DispositionVerdict.ACKNOWLEDGED, "analyst"
            )
        hist = await _fetch_historical_dispositions("60107", session)

    # The model must see only the 4 human verdicts — not a fabricated
    # "true-positive-heavy" history built from its own past output.
    assert hist["total_dispositions"] == 4
    assert hist["true_positive_count"] == 0
    assert hist["false_positive_rate"] == 1.0
    assert AI_ANALYST not in hist["analysts_involved"]
    assert all(ex["analyst"] != AI_ANALYST for ex in hist["recent_examples"])


async def test_agent_history_excludes_ai_dispositions():
    session_factory = await _make_session()
    async with session_factory() as session:
        for _ in range(10):
            await _insert_disposed_alert(
                session, "1001", DispositionVerdict.ACKNOWLEDGED, AI_ANALYST, agent_name="noisy"
            )
        await _insert_disposed_alert(
            session, "1002", DispositionVerdict.TRUE_POSITIVE, "analyst", agent_name="noisy"
        )
        hist = await _fetch_agent_history("noisy", session)

    # Ten AI auto-acks must not paint the host as noisy; the one human verdict
    # says the opposite.
    assert hist["total_alerts"] == 1
    assert hist["false_positive_rate"] == 0


async def test_rule_fp_rate_excludes_ai_dispositions():
    # The compounding-silence arm: AI auto-acks alone must never establish the
    # FP rate that feeds the noisy-OR dismiss confidence.
    session_factory = await _make_session()
    async with session_factory() as session:
        for _ in range(10):
            await _insert_disposed_alert(
                session, "2001", DispositionVerdict.ACKNOWLEDGED, AI_ANALYST
            )
        # Below the 5-human minimum -> no statistical signal at all.
        assert await _get_rule_fp_rate("2001", session) is None

        # With enough HUMAN history, the rate reflects humans only: 3 acks of
        # 6 human verdicts = 0.5, regardless of the 10 AI acks alongside.
        for _ in range(3):
            await _insert_disposed_alert(
                session, "2001", DispositionVerdict.ACKNOWLEDGED, "analyst"
            )
        for _ in range(3):
            await _insert_disposed_alert(
                session, "2001", DispositionVerdict.TRUE_POSITIVE, "analyst"
            )
        assert await _get_rule_fp_rate("2001", session) == 0.5
