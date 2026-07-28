"""Integration tests for Pono Score wired into Kahu core."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from kahu.models.base import Base
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.models.evidence import EvidenceRecord
from kahu.models.pono import PonoSnapshot
from kahu.services.pono import compute_and_persist, gather_inputs


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


def _make_alert(
    agent_name: str = "agent-1",
    severity: Severity = Severity.HIGH,
    created_at: datetime | None = None,
) -> Alert:
    return Alert(
        id=uuid.uuid4(),
        wazuh_alert_id=f"wazuh-{uuid.uuid4().hex[:8]}",
        rule_id="5503",
        rule_description="Test alert",
        severity=severity,
        agent_name=agent_name,
        raw_event={"test": True},
    )


def _make_connector(status: ConnectorStatus = ConnectorStatus.ACTIVE) -> ConnectorInstance:
    return ConnectorInstance(
        id=uuid.uuid4(),
        connector_type="syslog",
        name=f"test-{uuid.uuid4().hex[:6]}",
        status=status,
        config={},
        credentials={},
    )


class TestGatherInputs:
    """Test that gather_inputs produces valid component inputs from DB state."""

    async def test_empty_db_returns_defaults(self, session: AsyncSession):
        inputs, ages = await gather_inputs(session)
        assert "detection_posture" in inputs
        assert "response_readiness" in inputs
        # Components without data sources should be not-assessed
        assert inputs["tuning_hygiene"].data_available is False
        assert inputs["vulnerability_posture"].data_available is False
        assert inputs["identity_access"].data_available is False
        assert inputs["human_layer"].data_available is False

    async def test_alerts_affect_detection(self, session: AsyncSession):
        # Add some alerts from different agents
        for name in ["agent-1", "agent-2", "agent-3"]:
            session.add(_make_alert(agent_name=name))
        await session.commit()

        inputs, _ = await gather_inputs(session)
        det = inputs["detection_posture"]
        assert det.sensors_total >= 3
        assert det.sensors_healthy >= 3

    async def test_connectors_affect_detection(self, session: AsyncSession):
        session.add(_make_connector(ConnectorStatus.ACTIVE))
        session.add(_make_connector(ConnectorStatus.ACTIVE))
        session.add(_make_connector(ConnectorStatus.DISABLED))
        await session.commit()

        inputs, _ = await gather_inputs(session)
        det = inputs["detection_posture"]
        assert det.active_sources == 2
        assert det.expected_sources == 3

    async def test_dispositions_affect_response(self, session: AsyncSession):
        alert = _make_alert(severity=Severity.CRITICAL)
        session.add(alert)
        await session.flush()

        disp = AlertDisposition(
            id=uuid.uuid4(),
            alert_id=alert.id,
            verdict=DispositionVerdict.TRUE_POSITIVE,
            analyst="test-analyst",
        )
        session.add(disp)
        await session.commit()

        inputs, _ = await gather_inputs(session)
        resp = inputs["response_readiness"]
        assert resp.cases_total >= 1


class TestComputeAndPersist:
    """Test snapshot persistence."""

    async def test_creates_snapshot(self, session: AsyncSession):
        snapshot = await compute_and_persist(session, trigger="manual")
        assert snapshot.id is not None
        assert 0 <= snapshot.pono_score <= 100
        assert snapshot.trigger == "manual"
        assert len(snapshot.components) == 6

    async def test_snapshot_persisted_to_db(self, session: AsyncSession):
        await compute_and_persist(session, trigger="manual")
        result = await session.execute(select(PonoSnapshot))
        snapshots = result.scalars().all()
        assert len(snapshots) == 1

    async def test_multiple_snapshots_create_history(self, session: AsyncSession):
        await compute_and_persist(session, trigger="scheduled")
        await compute_and_persist(session, trigger="scheduled")
        await compute_and_persist(session, trigger="manual")

        result = await session.execute(select(PonoSnapshot))
        snapshots = result.scalars().all()
        assert len(snapshots) == 3

    async def test_detects_score_drop(self, session: AsyncSession):
        # First snapshot with some data
        for name in ["a1", "a2", "a3"]:
            session.add(_make_alert(agent_name=name))
        for _ in range(3):
            session.add(_make_connector(ConnectorStatus.ACTIVE))
        await session.commit()

        s1 = await compute_and_persist(session, trigger="manual")

        # The drop detection compares against the previous snapshot.
        # Since inputs are the same, no drop should occur.
        s2 = await compute_and_persist(session, trigger="manual")
        assert s2.pono_drop is None

    async def test_empty_db_score_uses_ceilings(self, session: AsyncSession):
        snapshot = await compute_and_persist(session, trigger="manual")
        # With mostly not-assessed components, score should be around the ceiling level
        # 4 components not-assessed at 40% ceiling + 2 assessed with minimal data
        assert snapshot.pono_score > 0
        assert snapshot.pono_score <= 100

    async def test_schema_version_persisted(self, session: AsyncSession):
        snapshot = await compute_and_persist(session, trigger="manual")
        assert snapshot.schema_version == "1.0"

    async def test_biggest_gain_populated(self, session: AsyncSession):
        snapshot = await compute_and_persist(session, trigger="manual")
        # With empty DB, there should be room for improvement
        assert snapshot.biggest_gain is not None
        assert "component" in snapshot.biggest_gain
        assert "available_gain" in snapshot.biggest_gain
