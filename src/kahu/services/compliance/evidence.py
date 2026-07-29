"""Append-only, hash-chained evidence recording service.

Any subsystem (triage, connectors, investigation, scans) can call
``record_evidence`` to produce a tamper-evident compliance record.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.evidence import EvidenceRecord

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


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
    previous_hash = await _get_latest_hash(session)

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
    record_hash = hashlib.sha256(record_content.encode()).hexdigest()

    record = EvidenceRecord(
        id=uuid.uuid4(),
        event_type=event_type,
        control_tags=control_tags,
        payload=payload,
        actor=actor,
        previous_hash=previous_hash,
        record_hash=record_hash,
    )
    session.add(record)
    logger.debug("Evidence recorded: type=%s actor=%s hash=%s", event_type, actor, record_hash[:12])
    return record


async def verify_chain(session: AsyncSession) -> tuple[bool, str | None]:
    """Walk the evidence chain and return ``(intact, broken_at_hash)``."""
    stmt = (
        select(EvidenceRecord.record_hash, EvidenceRecord.previous_hash)
        .order_by(EvidenceRecord.timestamp)
    )
    result = await session.execute(stmt)

    prev_hash: str | None = None
    for record_hash, previous_hash in result.all():
        if prev_hash is not None and previous_hash != prev_hash:
            return False, record_hash
        prev_hash = record_hash

    return True, None


async def _get_latest_hash(session: AsyncSession) -> str:
    stmt = (
        select(EvidenceRecord.record_hash)
        .order_by(desc(EvidenceRecord.timestamp))
        .limit(1)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    return row or GENESIS_HASH
