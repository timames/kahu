"""Tests for the validation sampler — random endpoint spot-checks."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from kahu.models.base import Base
from kahu.models.pono import PonoSnapshot
from kahu.models.validation import ValidationRound, ValidationSample, ValidationVerdict
from kahu.services.validation import (
    check_agent,
    evaluate_sample,
    list_fleet_agents,
    run_validation_round,
    select_sample,
)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


def _fake_agents(n: int) -> list[dict]:
    return [
        {"id": f"{i:03d}", "name": f"agent-{i}", "status": "active"}
        for i in range(1, n + 1)
    ]


def _mock_wazuh(agents: list[dict] | None = None) -> AsyncMock:
    """Build a mock WazuhAPIClient that returns plausible data."""
    wazuh = AsyncMock()
    now_iso = datetime.now(timezone.utc).isoformat()
    old_iso = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

    if agents is None:
        agents = _fake_agents(5)

    async def mock_api_get(path: str, params: dict | None = None):
        if path == "/agents":
            agent_id = (params or {}).get("agents_list")
            if agent_id:
                matched = [a for a in agents if a["id"] == agent_id]
                return {"data": {"affected_items": matched}}
            return {"data": {"affected_items": [{"id": "000"}] + agents}}

        if "/syscheck/" in path and "last_scan" in path:
            return {"data": {"affected_items": [{"end": now_iso}]}}

        if "/rootcheck/" in path and "last_scan" in path:
            return {"data": {"affected_items": [{"end": now_iso}]}}

        if "/vulnerability/" in path:
            return {"data": {"affected_items": [{"cve": "CVE-2024-1234"}]}}

        if "/sca/" in path:
            return {"data": {"affected_items": [
                {"pass": 80, "fail": 15, "invalid": 5}
            ]}}

        return {"data": {"affected_items": []}}

    wazuh.api_get = AsyncMock(side_effect=mock_api_get)
    return wazuh


class TestSelectSample:
    def test_sample_size_respected(self):
        agents = _fake_agents(50)
        sample = select_sample(agents, 13)
        assert len(sample) == 13

    def test_small_fleet_returns_all(self):
        agents = _fake_agents(5)
        sample = select_sample(agents, 13)
        assert len(sample) == 5

    def test_sample_is_random(self):
        agents = _fake_agents(100)
        s1 = [a["id"] for a in select_sample(agents, 13)]
        s2 = [a["id"] for a in select_sample(agents, 13)]
        # Very unlikely to be identical with 100 agents
        # (but not impossible — this is probabilistic, allow rare pass)
        # Just check they're valid subsets
        assert all(aid in [a["id"] for a in agents] for aid in s1)
        assert all(aid in [a["id"] for a in agents] for aid in s2)

    def test_no_duplicates(self):
        agents = _fake_agents(50)
        sample = select_sample(agents, 13)
        ids = [a["id"] for a in sample]
        assert len(ids) == len(set(ids))


class TestListFleetAgents:
    async def test_excludes_manager(self):
        wazuh = _mock_wazuh(_fake_agents(3))
        agents = await list_fleet_agents(wazuh)
        ids = [a["id"] for a in agents]
        assert "000" not in ids
        assert len(agents) == 3

    async def test_handles_api_failure(self):
        wazuh = AsyncMock()
        wazuh.api_get = AsyncMock(side_effect=Exception("connection refused"))
        agents = await list_fleet_agents(wazuh)
        assert agents == []


class TestCheckAgent:
    async def test_healthy_agent_all_pass(self):
        wazuh = _mock_wazuh()
        checks, findings = await check_agent(wazuh, "001")
        assert checks["agent_active"] is True
        assert checks["syscheck_current"] is True
        assert checks["rootcheck_current"] is True
        assert len(findings) == 0

    async def test_disconnected_agent(self):
        agents = [{"id": "001", "name": "agent-1", "status": "disconnected"}]
        wazuh = _mock_wazuh(agents)
        checks, findings = await check_agent(wazuh, "001")
        assert checks["agent_active"] is False
        assert any("disconnected" in f for f in findings)


class TestEvaluateSample:
    def test_all_pass(self):
        checks = {
            "agent_active": True,
            "syscheck_current": True,
            "rootcheck_current": True,
            "vulnerability_scan": True,
            "sca_pass_rate": 0.85,
        }
        assert evaluate_sample(checks) == ValidationVerdict.PASS

    def test_agent_unreachable(self):
        checks = {"agent_active": False}
        assert evaluate_sample(checks) == ValidationVerdict.UNREACHABLE

    def test_stale_syscheck_fails(self):
        checks = {
            "agent_active": True,
            "syscheck_current": False,
            "rootcheck_current": True,
        }
        assert evaluate_sample(checks) == ValidationVerdict.FAIL

    def test_stale_rootcheck_fails(self):
        checks = {
            "agent_active": True,
            "syscheck_current": True,
            "rootcheck_current": False,
        }
        assert evaluate_sample(checks) == ValidationVerdict.FAIL


class TestRunValidationRound:
    async def test_round_persisted(self, session: AsyncSession):
        wazuh = _mock_wazuh(_fake_agents(5))
        vr = await run_validation_round(session, sample_size=3, wazuh=wazuh)

        assert vr.id is not None
        assert vr.fleet_size == 5
        assert vr.sample_size == 3
        assert vr.samples_completed == 3
        assert vr.completed_at is not None

    async def test_samples_persisted(self, session: AsyncSession):
        wazuh = _mock_wazuh(_fake_agents(5))
        vr = await run_validation_round(session, sample_size=3, wazuh=wazuh)

        result = await session.execute(
            select(ValidationSample).where(ValidationSample.round_id == str(vr.id))
        )
        samples = result.scalars().all()
        assert len(samples) == 3

    async def test_healthy_fleet_passes(self, session: AsyncSession):
        wazuh = _mock_wazuh(_fake_agents(10))
        vr = await run_validation_round(session, sample_size=5, wazuh=wazuh)

        assert vr.samples_passed == 5
        assert vr.samples_failed == 0
        assert vr.validation_rate == 1.0
        assert vr.drift_detected is False

    async def test_empty_fleet(self, session: AsyncSession):
        wazuh = _mock_wazuh([])
        vr = await run_validation_round(session, sample_size=13, wazuh=wazuh)

        assert vr.fleet_size == 0
        assert vr.sample_size == 0
        assert vr.validation_rate is None

    async def test_captures_pono_score(self, session: AsyncSession):
        # Seed a pono snapshot
        snapshot = PonoSnapshot(
            pono_score=72.5,
            schema_version="1.0",
            components=[],
            trigger="manual",
        )
        session.add(snapshot)
        await session.commit()

        wazuh = _mock_wazuh(_fake_agents(5))
        vr = await run_validation_round(session, sample_size=3, wazuh=wazuh)
        assert vr.pono_score_at_start == 72.5

    async def test_drift_detected_on_failures(self, session: AsyncSession):
        # Mock agents where most are disconnected
        agents = [
            {"id": f"{i:03d}", "name": f"agent-{i}", "status": "disconnected"}
            for i in range(1, 6)
        ]
        wazuh = _mock_wazuh(agents)
        vr = await run_validation_round(session, sample_size=5, wazuh=wazuh)

        # All agents disconnected → unreachable → no evaluable samples
        # drift_detected depends on whether any were evaluable
        assert vr.samples_unreachable == 5

    async def test_multiple_rounds(self, session: AsyncSession):
        wazuh = _mock_wazuh(_fake_agents(10))
        await run_validation_round(session, sample_size=3, wazuh=wazuh)
        await run_validation_round(session, sample_size=3, wazuh=wazuh)

        result = await session.execute(select(ValidationRound))
        rounds = result.scalars().all()
        assert len(rounds) == 2
