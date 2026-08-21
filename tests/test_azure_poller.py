"""Tests for the Azure connector poller — cursor persistence, three-layer
dedup, per-instance failure isolation, and pipeline handoff."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from kahu.clients.azure import AzureAuthError
from kahu.models.alerts import Alert
from kahu.models.base import Base
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.services.connectors import azure_poller
from kahu.services.connectors.azure_poller import (
    _poll_instance,
    _record_poll_failure,
)
from kahu.services.triage.filters import DeduplicationWindow


@pytest.fixture(autouse=True)
def _reset_dedup():
    DeduplicationWindow.reset()
    yield
    DeduplicationWindow.reset()


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


class FakeOllama:
    """Unhealthy Ollama — triage degrades immediately, no network."""

    async def health(self) -> bool:
        return False


class FakeAzureClient:
    def __init__(self, graph_items=None, la_response=None, error: Exception | None = None):
        self.graph_items = graph_items or []
        self.la_response = la_response or {"tables": []}
        self.error = error
        self.calls: list[str] = []

    async def graph_get(self, path, params=None, max_items=200):
        self.calls.append(path)
        if self.error:
            raise self.error
        return self.graph_items[:max_items]

    async def la_query(self, workspace_id, kql, timespan=None):
        self.calls.append("la_query")
        if self.error:
            raise self.error
        return self.la_response


def _defender_item(alert_id: str, created: str, severity: str = "medium") -> dict:
    return {
        "id": alert_id,
        "title": f"Alert {alert_id}",
        "severity": severity,
        "category": "Execution",
        "createdDateTime": created,
        "evidence": [],
    }


def _instance(connector_type: str = "microsoft_defender", **cfg) -> ConnectorInstance:
    return ConnectorInstance(
        id=uuid.uuid4(),
        connector_type=connector_type,
        name=f"test-{connector_type}",
        status=ConnectorStatus.ACTIVE,
        config={"tenant_id": "t", "client_id": "c", "cloud_environment": "commercial", **cfg},
        credentials={"client_secret": "s"},
        # Fixed watermark: the fake client ignores server-side time filters, so
        # tests pin the cursor behind the fixture timestamps to make the
        # watermark-advance math deterministic.
        cursor={"watermark": "2026-08-20T09:00:00Z"},
    )


async def _alert_ids(session) -> set[str]:
    return set((await session.execute(select(Alert.wazuh_alert_id))).scalars())


class TestPollInstance:
    async def test_ingests_with_prefixed_ids_and_advances_cursor(self, session):
        inst = _instance()
        session.add(inst)
        await session.commit()

        client = FakeAzureClient(
            graph_items=[
                _defender_item("a1", "2026-08-20T10:00:00Z", "medium"),
                _defender_item("a2", "2026-08-20T10:05:00Z", "high"),
            ]
        )
        count = await _poll_instance(session, inst, client=client, ollama=FakeOllama())
        assert count == 2

        ids = await _alert_ids(session)
        assert {"defender:a1", "defender:a2"} <= ids

        assert inst.cursor["watermark"] == "2026-08-20T10:05:00Z"
        assert set(inst.cursor["seen_ids"]) == {"defender:a1", "defender:a2"}
        assert inst.events_total == 2
        assert inst.events_today == 2
        assert inst.error_message is None
        assert inst.last_event_at is not None

    async def test_cursor_survives_restart_no_reingest(self, session):
        """Simulated restart: cursor reloaded from DB, same feed re-fetched."""
        inst = _instance()
        session.add(inst)
        await session.commit()

        items = [_defender_item("a1", "2026-08-20T10:00:00Z")]
        client = FakeAzureClient(graph_items=items)
        assert await _poll_instance(session, inst, client=client, ollama=FakeOllama()) == 1

        # "Restart": re-load the instance fresh from the DB, poll again with
        # the boundary event still in the feed (inclusive `ge` overlap).
        iid = inst.id  # capture before expiring — expired attr access is sync
        session.expire_all()
        reloaded = await session.get(ConnectorInstance, iid)
        assert reloaded.cursor["watermark"] == "2026-08-20T10:00:00Z"
        assert await _poll_instance(session, reloaded, client=client, ollama=FakeOllama()) == 0
        assert len(await _alert_ids(session)) == 1

    async def test_db_precheck_catches_when_seen_ids_lost(self, session):
        """Layer 3: even with the seen-id ring wiped, the DB check dedups."""
        inst = _instance()
        session.add(inst)
        await session.commit()

        client = FakeAzureClient(graph_items=[_defender_item("a1", "2026-08-20T10:00:00Z")])
        await _poll_instance(session, inst, client=client, ollama=FakeOllama())

        inst.cursor = {**inst.cursor, "seen_ids": []}
        await session.commit()
        assert await _poll_instance(session, inst, client=client, ollama=FakeOllama()) == 0

    async def test_seen_ids_ring_bounded(self, session):
        inst = _instance()
        inst.cursor = {
            "watermark": "2026-08-20T00:00:00Z",
            "seen_ids": [f"defender:old{i}" for i in range(azure_poller.SEEN_IDS_MAX)],
        }
        session.add(inst)
        await session.commit()

        client = FakeAzureClient(graph_items=[_defender_item("new", "2026-08-20T10:00:00Z")])
        await _poll_instance(session, inst, client=client, ollama=FakeOllama())
        assert len(inst.cursor["seen_ids"]) == azure_poller.SEEN_IDS_MAX
        assert "defender:new" in inst.cursor["seen_ids"]

    async def test_entra_filter_applied(self, session):
        inst = _instance("entra_signin", signin_filter="risky_or_failed")
        session.add(inst)
        await session.commit()

        signins = [
            {  # risky — ingested
                "id": "s1",
                "createdDateTime": "2026-08-20T10:00:00Z",
                "userPrincipalName": "u1@x",
                "status": {"errorCode": 0},
                "riskLevelDuringSignIn": "high",
            },
            {  # clean success — filtered out client-side
                "id": "s2",
                "createdDateTime": "2026-08-20T10:01:00Z",
                "userPrincipalName": "u2@x",
                "status": {"errorCode": 0},
                "riskLevelDuringSignIn": "none",
            },
        ]
        client = FakeAzureClient(graph_items=signins)
        count = await _poll_instance(session, inst, client=client, ollama=FakeOllama())
        assert count == 1
        assert "entra:s1" in await _alert_ids(session)
        assert "entra:s2" not in await _alert_ids(session)

    async def test_log_analytics_rows_ingested(self, session):
        inst = _instance(
            "azure_log_analytics",
            workspace_id="ws-1",
            kql_query="SecurityEvent | take 1",
            query_name="Test query",
            default_level="10",
        )
        session.add(inst)
        await session.commit()

        client = FakeAzureClient(
            la_response={
                "tables": [
                    {
                        "columns": [{"name": "Computer"}, {"name": "EventID"}],
                        "rows": [["srv1", 4625]],
                    }
                ]
            }
        )
        count = await _poll_instance(session, inst, client=client, ollama=FakeOllama())
        assert count == 1
        ids = await _alert_ids(session)
        assert any(i.startswith("la:") for i in ids)


class TestFailureHandling:
    async def test_auth_failure_marks_error(self, session):
        inst = _instance()
        session.add(inst)
        await session.commit()

        await _record_poll_failure(session, inst, AzureAuthError("AADSTS7000215 bad secret"))
        assert inst.status == ConnectorStatus.ERROR
        assert "AADSTS7000215" in inst.error_message

    async def test_transient_5xx_stays_active(self, session):
        inst = _instance()
        session.add(inst)
        await session.commit()

        req = httpx.Request("GET", "https://graph.microsoft.com/x")
        exc = httpx.HTTPStatusError("boom", request=req, response=httpx.Response(503, request=req))
        await _record_poll_failure(session, inst, exc)
        assert inst.status == ConnectorStatus.ACTIVE
        assert inst.error_message is not None

    async def test_graph_403_marks_error(self, session):
        inst = _instance()
        session.add(inst)
        await session.commit()

        req = httpx.Request("GET", "https://graph.microsoft.com/x")
        exc = httpx.HTTPStatusError(
            "forbidden", request=req, response=httpx.Response(403, request=req)
        )
        await _record_poll_failure(session, inst, exc)
        assert inst.status == ConnectorStatus.ERROR

    async def test_one_failing_instance_does_not_block_others(self, session, monkeypatch):
        good = _instance()
        bad = _instance("entra_signin")
        # Deterministic iteration order: bad first, good second.
        session.add_all([bad, good])
        await session.commit()

        clients = {
            str(bad.id): FakeAzureClient(error=AzureAuthError("AADSTS7000215")),
            str(good.id): FakeAzureClient(
                graph_items=[_defender_item("g1", "2026-08-20T10:00:00Z")]
            ),
        }
        monkeypatch.setattr(azure_poller, "_build_client", lambda inst: clients[str(inst.id)])
        monkeypatch.setattr(azure_poller, "OllamaClient", FakeOllama)

        # Replicate the poll_all loop body (iterate by id, re-get per
        # instance) over the test session, bad instance first.
        result = await session.execute(
            select(ConnectorInstance.id).where(
                ConnectorInstance.connector_type.in_(azure_poller.AZURE_CONNECTOR_TYPES),
                ConnectorInstance.status == ConnectorStatus.ACTIVE,
            )
        )
        instance_ids = sorted(result.scalars(), key=lambda i: i != bad.id)
        total = 0
        for instance_id in instance_ids:
            instance = await session.get(ConnectorInstance, instance_id)
            try:
                total += await _poll_instance(session, instance)
            except Exception as exc:
                await azure_poller._record_poll_failure(session, instance, exc)

        assert total == 1
        assert "defender:g1" in await _alert_ids(session)
        assert bad.status == ConnectorStatus.ERROR
        assert good.status == ConnectorStatus.ACTIVE
