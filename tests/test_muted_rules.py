"""User rule mutes — LLM-cost suppression with the governing invariant intact.

A muted rule's alerts are still persisted (audit trail) but skip enrichment,
LLM triage, and auto-disposition, and are hidden from the pending queue.

Properties under test:
1. Muted alert is persisted minimal (muted=True, no llm_triage, provenance
   stamped) and the Ollama client is never touched.
2. Guardrail: CRITICAL_RULE_IDS can never be muted — full triage runs anyway.
3. Guardrail: deterministic high/critical severity ignores the mute.
4. An expired mute is inert — normal triage.
5. The queue hides muted alerts; history shows them flagged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# aiosqlite is a declared dev dependency and these cases must FAIL, not skip,
# if it is missing — a silently skipped security regression test is the same as
# no test at all.
import aiosqlite  # noqa: F401
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import kahu.models  # noqa: F401  — register every table on Base.metadata
from kahu.api.triage import alert_history, get_triage_queue
from kahu.models.alerts import Alert, MutedRule
from kahu.models.base import Base
from kahu.services.triage.filters import CRITICAL_RULE_IDS, DeduplicationWindow
from kahu.services.triage.pipeline import get_active_muted_rule_ids, run_pipeline


class FakeOllama:
    """Records every call — a muted alert must never reach the model."""

    def __init__(self) -> None:
        self.health_calls = 0
        self.generate_calls = 0

    async def health(self) -> bool:
        self.health_calls += 1
        # Report unhealthy so full-triage paths take the degraded branch —
        # these tests care about *whether* the model was consulted, not output.
        return False

    async def generate(self, *args, **kwargs) -> str:
        self.generate_calls += 1
        return "{}"


async def _make_session():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


def _raw_alert(rule_id: str, level: int = 7, agent: str = "host1") -> dict:
    return {
        "id": f"wazuh-{rule_id}-{agent}-{level}",
        "rule": {"id": rule_id, "level": level, "description": f"rule {rule_id}", "groups": []},
        "agent": {"name": agent},
    }


def _mute(rule_id: str, expires_at: datetime | None = None, active: bool = True) -> MutedRule:
    return MutedRule(
        rule_id=rule_id,
        reason="test",
        created_by="analyst@test",
        expires_at=expires_at,
        active=active,
    )


async def test_muted_rule_skips_llm_and_is_persisted_muted():
    DeduplicationWindow.reset()
    session_factory = await _make_session()
    ollama = FakeOllama()
    async with session_factory() as session:
        session.add(_mute("60107"))
        await session.commit()

        muted_rules = await get_active_muted_rule_ids(session)
        assert muted_rules == {"60107"}

        result = await run_pipeline(
            _raw_alert("60107"), session=session, ollama=ollama, muted_rules=muted_rules
        )

        assert result.passed_filter is True
        assert result.muted is True
        assert result.llm_output is None
        assert result.enrichment is None
        assert result.provenance["muted_by_rule"] == "60107"
        assert result.provenance["stages"] == ["filters", "muted"]
        # The whole point: zero model cost.
        assert ollama.health_calls == 0
        assert ollama.generate_calls == 0

        alert = (await session.execute(select(Alert))).scalar_one()
        assert alert.muted is True
        assert alert.llm_triage is None
        assert alert.pipeline_provenance["muted_by_rule"] == "60107"


async def test_mute_on_critical_rule_is_ignored():
    DeduplicationWindow.reset()
    session_factory = await _make_session()
    ollama = FakeOllama()
    critical_rule = next(iter(CRITICAL_RULE_IDS))
    async with session_factory() as session:
        session.add(_mute(critical_rule))
        await session.commit()
        muted_rules = await get_active_muted_rule_ids(session)

        result = await run_pipeline(
            _raw_alert(critical_rule, level=5),
            session=session,
            ollama=ollama,
            muted_rules=muted_rules,
        )

        # Full triage path ran — the mute never applied.
        assert result.muted is False
        assert result.llm_output is not None
        assert ollama.health_calls > 0

        alert = (await session.execute(select(Alert))).scalar_one()
        assert alert.muted is False


async def test_mute_ignored_for_high_severity_alert():
    DeduplicationWindow.reset()
    session_factory = await _make_session()
    ollama = FakeOllama()
    async with session_factory() as session:
        session.add(_mute("5555"))
        await session.commit()
        muted_rules = await get_active_muted_rule_ids(session)

        # Level 10 -> deterministic "high": mute must not apply.
        result = await run_pipeline(
            _raw_alert("5555", level=10),
            session=session,
            ollama=ollama,
            muted_rules=muted_rules,
        )

        assert result.muted is False
        assert result.llm_output is not None
        assert ollama.health_calls > 0


async def test_expired_mute_is_inert():
    DeduplicationWindow.reset()
    session_factory = await _make_session()
    ollama = FakeOllama()
    async with session_factory() as session:
        session.add(_mute("7777", expires_at=datetime.now(UTC) - timedelta(hours=1)))
        session.add(_mute("8888", active=False))
        await session.commit()

        muted_rules = await get_active_muted_rule_ids(session)
        assert muted_rules == set()

        result = await run_pipeline(
            _raw_alert("7777"), session=session, ollama=ollama, muted_rules=muted_rules
        )
        assert result.muted is False
        assert result.llm_output is not None
        assert ollama.health_calls > 0


async def test_queue_hides_muted_history_shows_them():
    DeduplicationWindow.reset()
    session_factory = await _make_session()
    ollama = FakeOllama()
    async with session_factory() as session:
        session.add(_mute("60107"))
        await session.commit()
        muted_rules = await get_active_muted_rule_ids(session)

        await run_pipeline(
            _raw_alert("60107"), session=session, ollama=ollama, muted_rules=muted_rules
        )
        await run_pipeline(
            _raw_alert("3333", agent="host2"),
            session=session,
            ollama=ollama,
            muted_rules=muted_rules,
        )

        queue = await get_triage_queue(
            severity=None, undispositioned_only=True, offset=0, limit=50, session=session
        )
        assert queue.total == 1
        assert queue.alerts[0].rule_id == "3333"

        history = await alert_history(
            severity=None, verdict=None, search=None, offset=0, limit=50, session=session
        )
        assert history.total == 2
        by_rule = {a.rule_id: a for a in history.alerts}
        assert by_rule["60107"].muted is True
        assert by_rule["3333"].muted is False
