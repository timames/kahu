"""Alert → escalate → investigation → promote → incident → close flow.

Regression suite for kahu.services.tickets: idempotent ticket creation
(Ticket.alert_id is UNIQUE and three call sites create tickets), disposition
UPSERT on promote/close (AlertDisposition.alert_id is UNIQUE), and the
evidence trail for every case transition.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.base import Base
from kahu.models.evidence import EvidenceRecord
from kahu.models.tickets import Ticket, TicketStatus, TicketType
from kahu.services.compliance.evidence import verify_chain
from kahu.services.tickets import (
    close_ticket_with_verdict,
    ensure_ticket_for_verdict,
    promote_ticket,
)
from kahu.services.triage.disposition import record_disposition


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


def _make_alert(severity: Severity = Severity.MEDIUM) -> Alert:
    return Alert(
        id=uuid.uuid4(),
        wazuh_alert_id=f"wazuh-{uuid.uuid4().hex[:8]}",
        rule_id="5503",
        rule_description="Test alert",
        severity=severity,
        agent_name="agent-1",
        raw_event={"test": True},
    )


async def _persist_alert(session: AsyncSession, severity: Severity = Severity.MEDIUM) -> Alert:
    alert = _make_alert(severity)
    session.add(alert)
    await session.commit()
    return alert


async def _evidence_types(session: AsyncSession) -> list[str]:
    result = await session.execute(
        select(EvidenceRecord.event_type).order_by(EvidenceRecord.timestamp)
    )
    return [row[0] for row in result.all()]


class TestEnsureTicketForVerdict:
    async def test_undetermined_opens_investigation(self, session: AsyncSession):
        alert = await _persist_alert(session)
        await record_disposition(
            alert_id=alert.id,
            verdict=DispositionVerdict.UNDETERMINED,
            analyst="alice",
            notes="escalating",
            session=session,
        )
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.UNDETERMINED, "alice"
        )
        await session.commit()

        assert ticket is not None
        assert ticket.ticket_type == TicketType.INVESTIGATION.value
        assert ticket.status == TicketStatus.OPEN
        assert ticket.assigned_to == "alice"
        assert "alert_escalated" in await _evidence_types(session)

    async def test_repeat_call_is_idempotent(self, session: AsyncSession):
        alert = await _persist_alert(session)
        first = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.UNDETERMINED, "alice"
        )
        await session.commit()
        # A second call (e.g. duplicate escalate) must return the same row
        # instead of tripping the alert_id unique constraint.
        second = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.UNDETERMINED, "bob"
        )
        await session.commit()

        assert first is not None and second is not None
        assert first.id == second.id
        count = len((await session.execute(select(Ticket))).scalars().all())
        assert count == 1

    async def test_true_positive_opens_incident(self, session: AsyncSession):
        alert = await _persist_alert(session, Severity.HIGH)
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.TRUE_POSITIVE, "alice"
        )
        await session.commit()

        assert ticket is not None
        assert ticket.ticket_type == TicketType.INCIDENT.value
        assert ticket.severity == "high"
        assert "incident_opened" in await _evidence_types(session)

    async def test_acknowledged_creates_no_ticket(self, session: AsyncSession):
        alert = await _persist_alert(session)
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.ACKNOWLEDGED, "alice"
        )
        assert ticket is None
        count = len((await session.execute(select(Ticket))).scalars().all())
        assert count == 0


class TestPromoteTicket:
    async def test_promote_flips_type_and_updates_disposition(self, session: AsyncSession):
        alert = await _persist_alert(session)
        # Escalation path: disposition row exists (undetermined) + investigation.
        original = await record_disposition(
            alert_id=alert.id,
            verdict=DispositionVerdict.UNDETERMINED,
            analyst="alice",
            notes=None,
            session=session,
        )
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.UNDETERMINED, "alice"
        )
        await session.commit()
        assert ticket is not None

        await promote_ticket(session, ticket, analyst="bob")
        await session.commit()

        assert ticket.ticket_type == TicketType.INCIDENT.value
        assert ticket.promoted_by == "bob"
        assert ticket.promoted_at is not None

        # Same disposition row, updated in place — not a second insert.
        rows = (await session.execute(select(AlertDisposition))).scalars().all()
        assert len(rows) == 1
        assert rows[0].id == original.id
        assert rows[0].verdict == DispositionVerdict.TRUE_POSITIVE
        assert rows[0].analyst == "bob"

        assert "investigation_promoted" in await _evidence_types(session)


class TestCloseTicket:
    @pytest.mark.parametrize(
        ("verdict", "expected"),
        [
            ("true_positive", DispositionVerdict.TRUE_POSITIVE),
            ("false_positive", DispositionVerdict.ACKNOWLEDGED),  # legacy folds
            ("acknowledged", DispositionVerdict.ACKNOWLEDGED),
        ],
    )
    async def test_close_each_verdict(
        self, session: AsyncSession, verdict: str, expected: DispositionVerdict
    ):
        alert = await _persist_alert(session)
        await record_disposition(
            alert_id=alert.id,
            verdict=DispositionVerdict.UNDETERMINED,
            analyst="alice",
            notes=None,
            session=session,
        )
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.UNDETERMINED, "alice"
        )
        await session.commit()
        assert ticket is not None

        await close_ticket_with_verdict(
            session, ticket, verdict=verdict, notes="resolved it", analyst="carol"
        )
        await session.commit()

        assert ticket.status == TicketStatus.CLOSED
        assert ticket.closed_by == "carol"
        assert ticket.resolution_notes == "resolved it"

        rows = (await session.execute(select(AlertDisposition))).scalars().all()
        assert len(rows) == 1
        assert rows[0].verdict == expected
        assert rows[0].analyst == "carol"
        assert rows[0].notes == "resolved it"

        types = await _evidence_types(session)
        assert "ticket_closed" in types
        intact, broken_at = await verify_chain(session)
        assert intact, f"evidence chain broken at {broken_at}"

    async def test_close_inserts_disposition_when_absent(self, session: AsyncSession):
        # A ticket whose alert has no disposition row (insert branch).
        alert = await _persist_alert(session)
        ticket = Ticket(
            alert_id=alert.id,
            title="orphan case",
            severity="medium",
            ticket_type=TicketType.INVESTIGATION.value,
            status=TicketStatus.OPEN,
            assigned_to="alice",
        )
        session.add(ticket)
        await session.commit()

        await close_ticket_with_verdict(
            session, ticket, verdict="true_positive", notes="confirmed", analyst="carol"
        )
        await session.commit()

        rows = (await session.execute(select(AlertDisposition))).scalars().all()
        assert len(rows) == 1
        assert rows[0].alert_id == alert.id
        assert rows[0].verdict == DispositionVerdict.TRUE_POSITIVE
        assert rows[0].analyst == "carol"

    async def test_close_rejects_invalid_verdict(self, session: AsyncSession):
        alert = await _persist_alert(session)
        ticket = await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.TRUE_POSITIVE, "alice"
        )
        await session.commit()
        assert ticket is not None

        with pytest.raises(ValueError, match="Invalid closing verdict"):
            await close_ticket_with_verdict(
                session, ticket, verdict="escalate", notes="x", analyst="carol"
            )
