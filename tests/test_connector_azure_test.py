"""Tests for the real Azure connection test — probe dispatch selection and
actionable failure-message mapping."""

from __future__ import annotations

import uuid

import httpx
import pytest

from kahu.clients.azure import CLOUDS, AzureAuthError
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.services.connectors.azure_test import AZURE_TEST_TYPES, run_azure_test


def _instance(connector_type: str = "microsoft_defender", **cfg) -> ConnectorInstance:
    return ConnectorInstance(
        id=uuid.uuid4(),
        connector_type=connector_type,
        name="t",
        status=ConnectorStatus.PENDING,
        config={"tenant_id": "t", "client_id": "c", "cloud_environment": "commercial", **cfg},
        credentials={"client_secret": "s"},
    )


class FakeClient:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.graph_paths: list[str] = []
        self.la_calls: list[tuple] = []

    async def graph_get(self, path, params=None, max_items=200):
        self.graph_paths.append(path)
        if self.error:
            raise self.error
        return []

    async def la_query(self, workspace_id, kql, timespan=None):
        self.la_calls.append((workspace_id, kql))
        if self.error:
            raise self.error
        return {"tables": []}


def _http_error(status: int) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://graph.microsoft.com/x")
    return httpx.HTTPStatusError("err", request=req, response=httpx.Response(status, request=req))


class TestDispatch:
    def test_types_registered(self):
        assert {"microsoft_defender", "azure_log_analytics", "entra_signin"} == AZURE_TEST_TYPES

    def test_cloud_map_covers_both_clouds(self):
        assert set(CLOUDS) == {"commercial", "gcc_high"}
        assert CLOUDS["gcc_high"]["graph"] == "https://graph.microsoft.us"
        assert CLOUDS["gcc_high"]["login"] == "https://login.microsoftonline.us"

    async def test_defender_probes_alerts_v2(self):
        client = FakeClient()
        ok, msg = await run_azure_test(_instance("microsoft_defender"), client=client)
        assert ok
        assert client.graph_paths == ["/v1.0/security/alerts_v2"]

    async def test_entra_probes_signins(self):
        client = FakeClient()
        ok, _ = await run_azure_test(_instance("entra_signin"), client=client)
        assert ok
        assert client.graph_paths == ["/v1.0/auditLogs/signIns"]

    async def test_la_probes_workspace_query(self):
        client = FakeClient()
        inst = _instance("azure_log_analytics", workspace_id="ws-9")
        ok, _ = await run_azure_test(inst, client=client)
        assert ok
        assert client.la_calls[0][0] == "ws-9"


class TestFailureMapping:
    async def test_invalid_secret_message(self):
        client = FakeClient(error=AzureAuthError("AADSTS7000215: Invalid client secret provided"))
        ok, msg = await run_azure_test(_instance(), client=client)
        assert not ok
        assert "secret is invalid" in msg

    async def test_unknown_tenant_message(self):
        client = FakeClient(error=AzureAuthError("AADSTS90002: Tenant not found"))
        ok, msg = await run_azure_test(_instance(), client=client)
        assert not ok
        assert "Tenant ID" in msg

    async def test_missing_permission_names_the_permission(self):
        client = FakeClient(error=_http_error(403))
        ok, msg = await run_azure_test(_instance("microsoft_defender"), client=client)
        assert not ok
        assert "SecurityAlert.Read.All" in msg
        assert "admin consent" in msg

    async def test_entra_permission_message(self):
        client = FakeClient(error=_http_error(403))
        ok, msg = await run_azure_test(_instance("entra_signin"), client=client)
        assert not ok
        assert "AuditLog.Read.All" in msg

    async def test_workspace_not_found(self):
        client = FakeClient(error=_http_error(404))
        inst = _instance("azure_log_analytics", workspace_id="ws-9")
        ok, msg = await run_azure_test(inst, client=client)
        assert not ok
        assert "workspace" in msg.lower()

    async def test_network_error(self):
        client = FakeClient(error=httpx.ConnectError("refused"))
        ok, msg = await run_azure_test(_instance(), client=client)
        assert not ok
        assert "Could not reach" in msg


@pytest.mark.parametrize("ct", sorted(AZURE_TEST_TYPES))
def test_catalog_has_azure_types(ct):
    from kahu.services.connectors.catalog import CATALOG

    entry = CATALOG[ct]
    field_names = {f.name for f in entry.fields}
    assert {"tenant_id", "client_id", "client_secret", "cloud_environment"} <= field_names
