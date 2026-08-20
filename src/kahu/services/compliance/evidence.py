"""Append-only, hash-chained evidence recording service.

Any subsystem (triage, connectors, investigation, scans) can call
``record_evidence`` to produce a tamper-evident compliance record.

Chain integrity under concurrency
---------------------------------
A hash chain needs a single writer at its head. Kahu has several concurrent
evidence producers (poller, reeval, auto-disposition, API handlers), and the
original implementation picked the head by ``timestamp`` — which is not a
total order (concurrent transactions share ``now()``), so two writers could
read the same head and fork the chain into a DAG.

Two mechanisms fix that:

- ``sequence`` — a monotonic integer assigned here, giving the chain an
  explicit total order independent of timestamps.
- On Postgres, ``pg_advisory_xact_lock`` serialises appends: the lock is
  taken before reading the head and held until the *caller's* commit (the
  caller owns the commit — that convention is unchanged), so no two
  transactions can chain off the same head. SQLite is a single-writer
  engine used only in dev/tests, so the lock is skipped there.

``relinearize_chain`` exists to repair stores written before this fix: it
rewrites ``previous_hash``/``record_hash`` in ``sequence`` order to restore
one linear chain. That is an explicit, one-time mutation of the store — run
it deliberately, and record an evidence entry documenting the repair.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.evidence import EvidenceRecord

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# Arbitrary but stable 64-bit key for pg_advisory_xact_lock — one global
# lock for the single evidence chain head.
_CHAIN_LOCK_KEY = int.from_bytes(b"kahuevid", "big", signed=True)


def _compute_record_hash(
    *,
    previous_hash: str,
    event_type: str,
    control_tags: list[str],
    payload: dict,
    actor: str | None,
) -> str:
    record_content = json.dumps(
        {
            "previous_hash": previous_hash,
            "event_type": event_type,
            "control_tags": control_tags,
            "payload": payload,
            "actor": actor,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(record_content.encode()).hexdigest()


async def record_evidence(
    session: AsyncSession,
    *,
    event_type: str,
    control_tags: list[str],
    payload: dict,
    actor: str,
) -> EvidenceRecord:
    """Append a hash-chained record to the evidence store.

    Parameters
    ----------
    session:
        Active DB session. Caller is responsible for ``commit``.
    event_type:
        Category such as ``alert_raised``, ``alert_dispositioned``,
        ``connector_configured``, ``scan_completed``, ``investigation_opened``.
    control_tags:
        Compliance control identifiers (e.g. ``800-171:3.3.1``, ``SOC2:CC7.1``).
    payload:
        Arbitrary JSON-serialisable evidence body.
    actor:
        Who/what produced this record (``system:triage_pipeline``, username, …).
    """
    # Serialise appends across transactions. The advisory lock is
    # transaction-scoped: it releases at the caller's commit/rollback, so the
    # head cannot move under us between reading it and committing our record.
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": _CHAIN_LOCK_KEY}
        )

    previous_hash, previous_sequence = await _get_chain_head(session)
    record_hash = _compute_record_hash(
        previous_hash=previous_hash,
        event_type=event_type,
        control_tags=control_tags,
        payload=payload,
        actor=actor,
    )

    record = EvidenceRecord(
        id=uuid.uuid4(),
        event_type=event_type,
        control_tags=control_tags,
        payload=payload,
        actor=actor,
        previous_hash=previous_hash,
        record_hash=record_hash,
        sequence=previous_sequence + 1,
    )
    session.add(record)
    logger.debug("Evidence recorded: type=%s actor=%s hash=%s", event_type, actor, record_hash[:12])
    return record


async def verify_chain(session: AsyncSession) -> tuple[bool, str | None]:
    """Walk the evidence chain in ``sequence`` order and return
    ``(intact, broken_at_hash)``."""
    stmt = select(EvidenceRecord.record_hash, EvidenceRecord.previous_hash).order_by(
        EvidenceRecord.sequence
    )
    result = await session.execute(stmt)

    prev_hash: str | None = None
    for record_hash, previous_hash in result.all():
        if prev_hash is not None and previous_hash != prev_hash:
            return False, record_hash
        prev_hash = record_hash

    return True, None


async def relinearize_chain(session: AsyncSession) -> int:
    """One-time repair: rewrite the chain into a single line in ``sequence``
    order, recomputing hashes where links are broken.

    Returns the number of records rewritten. Caller owns the commit and
    should record an evidence entry documenting the repair.
    """
    result = await session.execute(select(EvidenceRecord).order_by(EvidenceRecord.sequence))
    records = result.scalars().all()

    prev_hash = GENESIS_HASH
    fixed = 0
    for record in records:
        expected_hash = _compute_record_hash(
            previous_hash=prev_hash,
            event_type=record.event_type,
            control_tags=record.control_tags,
            payload=record.payload,
            actor=record.actor,
        )
        if record.previous_hash != prev_hash or record.record_hash != expected_hash:
            record.previous_hash = prev_hash
            record.record_hash = expected_hash
            fixed += 1
        prev_hash = record.record_hash

    logger.info("Evidence chain relinearized: %d of %d records rewritten", fixed, len(records))
    return fixed


async def _get_chain_head(session: AsyncSession) -> tuple[str, int]:
    stmt = (
        select(EvidenceRecord.record_hash, EvidenceRecord.sequence)
        .order_by(desc(EvidenceRecord.sequence))
        .limit(1)
    )
    result = await session.execute(stmt)
    row = result.one_or_none()
    if row is None:
        return GENESIS_HASH, 0
    return row.record_hash, row.sequence
