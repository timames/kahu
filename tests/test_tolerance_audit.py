"""The auto-dispose tolerance dial is an audited, attributable change.

Tolerance is a global suppression-posture lever for the whole appliance. Moving
it to "aggressive" lowers the auto-dismiss bar everywhere, so a change must land
in the hash-chained evidence store with who made it — otherwise the one global
knob that widens the system's blind spot leaves no trace.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiosqlite")

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import kahu.models  # noqa: F401,E402  — register every table on Base.metadata
from kahu.models.base import Base  # noqa: E402
from kahu.models.evidence import EvidenceRecord  # noqa: E402
from kahu.services.triage.auto_disposition import (  # noqa: E402
    TOLERANCE_CHANGE_CONTROLS,
    get_tolerance,
    set_tolerance,
    set_tolerance_audited,
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


@pytest.fixture(autouse=True)
def _restore_tolerance():
    # The tolerance is process-global; don't leak state across tests.
    original = get_tolerance()
    yield
    set_tolerance(original)


async def _fetch_evidence(session) -> list[EvidenceRecord]:
    result = await session.execute(select(EvidenceRecord))
    return list(result.scalars().all())


async def test_tolerance_change_writes_attributed_evidence():
    set_tolerance(2)  # start Balanced
    session_factory = await _make_session()
    async with session_factory() as session:
        level = await set_tolerance_audited(3, session=session, actor="admin@example.com")
        assert level == 3
        assert get_tolerance() == 3

        records = await _fetch_evidence(session)
    assert len(records) == 1
    rec = records[0]
    assert rec.event_type == "auto_disposition_tolerance_changed"
    assert rec.actor == "admin@example.com"
    assert rec.control_tags == TOLERANCE_CHANGE_CONTROLS
    assert rec.payload["old_level"] == 2
    assert rec.payload["new_level"] == 3
    assert rec.payload["changed"] is True
    assert rec.payload["new_label"] == "Aggressive"
    # Hash-chained: genesis previous, non-empty record hash.
    assert rec.previous_hash == "0" * 64
    assert len(rec.record_hash) == 64


async def test_out_of_range_level_is_clamped_and_recorded():
    set_tolerance(2)
    session_factory = await _make_session()
    async with session_factory() as session:
        level = await set_tolerance_audited(99, session=session, actor="admin@example.com")
        assert level == 3  # clamped to aggressive
        records = await _fetch_evidence(session)
    assert records[0].payload["new_level"] == 3


async def test_noop_change_is_still_recorded():
    # An explicit set to the same level is still an event worth attributing.
    set_tolerance(2)
    session_factory = await _make_session()
    async with session_factory() as session:
        await set_tolerance_audited(2, session=session, actor="analyst@example.com")
        records = await _fetch_evidence(session)
    assert len(records) == 1
    assert records[0].payload["changed"] is False
