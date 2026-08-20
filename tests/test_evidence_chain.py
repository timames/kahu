"""Evidence chain integrity: total order via sequence + fork repair.

The chain historically forked under concurrent writers because the head was
selected by timestamp (not a total order). These tests pin the fixed
behaviour: monotonic sequence assignment, sequence-ordered verification,
and relinearize_chain() repairing a forked store.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from kahu.models.base import Base
from kahu.models.evidence import EvidenceRecord
from kahu.services.compliance.evidence import (
    GENESIS_HASH,
    _compute_record_hash,
    record_evidence,
    relinearize_chain,
    verify_chain,
)


@pytest.fixture
async def session():
    """Create an in-memory SQLite async session for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


async def _append(session: AsyncSession, n: int) -> list[EvidenceRecord]:
    records = []
    for i in range(n):
        records.append(
            await record_evidence(
                session,
                event_type=f"test_event_{i}",
                control_tags=["800-171:3.3.1"],
                payload={"i": i},
                actor="tester",
            )
        )
    await session.commit()
    return records


class TestSequenceAssignment:
    async def test_sequences_are_monotonic_from_one(self, session: AsyncSession):
        records = await _append(session, 3)
        assert [r.sequence for r in records] == [1, 2, 3]

    async def test_first_record_chains_from_genesis(self, session: AsyncSession):
        (record,) = await _append(session, 1)
        assert record.previous_hash == GENESIS_HASH

    async def test_each_record_chains_from_previous(self, session: AsyncSession):
        records = await _append(session, 3)
        assert records[1].previous_hash == records[0].record_hash
        assert records[2].previous_hash == records[1].record_hash

    async def test_multiple_appends_within_one_transaction(self, session: AsyncSession):
        # No commit between appends — the head query must still see the
        # pending record (autoflush) rather than forking off the same head.
        a = await record_evidence(
            session, event_type="a", control_tags=[], payload={}, actor="t"
        )
        b = await record_evidence(
            session, event_type="b", control_tags=[], payload={}, actor="t"
        )
        await session.commit()
        assert b.previous_hash == a.record_hash
        assert b.sequence == a.sequence + 1

    async def test_verify_chain_intact(self, session: AsyncSession):
        await _append(session, 5)
        intact, broken_at = await verify_chain(session)
        assert intact
        assert broken_at is None


def _forked_record(previous_hash: str, sequence: int, tag: str) -> EvidenceRecord:
    """Build a record chaining off an arbitrary head — simulates the
    pre-fix concurrent writer that read a stale head."""
    payload = {"tag": tag}
    return EvidenceRecord(
        id=uuid.uuid4(),
        event_type="forked_event",
        control_tags=[],
        payload=payload,
        actor="racer",
        previous_hash=previous_hash,
        record_hash=_compute_record_hash(
            previous_hash=previous_hash,
            event_type="forked_event",
            control_tags=[],
            payload=payload,
            actor="racer",
        ),
        sequence=sequence,
    )


class TestRelinearize:
    async def test_fork_is_detected_then_repaired(self, session: AsyncSession):
        records = await _append(session, 3)
        # Two "concurrent" writers both chained off record 1's hash.
        session.add(_forked_record(records[0].record_hash, sequence=4, tag="x"))
        session.add(_forked_record(records[0].record_hash, sequence=5, tag="y"))
        await session.commit()

        intact, broken_at = await verify_chain(session)
        assert not intact
        assert broken_at is not None

        fixed = await relinearize_chain(session)
        await session.commit()
        assert fixed == 2  # only the forked records needed rewriting

        intact, broken_at = await verify_chain(session)
        assert intact

    async def test_repaired_hashes_are_recomputable(self, session: AsyncSession):
        records = await _append(session, 2)
        session.add(_forked_record(records[0].record_hash, sequence=3, tag="x"))
        await session.commit()
        await relinearize_chain(session)
        await session.commit()

        rows = (
            (await session.execute(select(EvidenceRecord).order_by(EvidenceRecord.sequence)))
            .scalars()
            .all()
        )
        prev = GENESIS_HASH
        for row in rows:
            assert row.previous_hash == prev
            assert row.record_hash == _compute_record_hash(
                previous_hash=prev,
                event_type=row.event_type,
                control_tags=row.control_tags,
                payload=row.payload,
                actor=row.actor,
            )
            prev = row.record_hash

    async def test_new_appends_chain_onto_repaired_head(self, session: AsyncSession):
        records = await _append(session, 2)
        session.add(_forked_record(records[0].record_hash, sequence=3, tag="x"))
        await session.commit()
        await relinearize_chain(session)
        await session.commit()

        (new,) = await _append(session, 1)
        assert new.sequence == 4
        intact, _ = await verify_chain(session)
        assert intact
