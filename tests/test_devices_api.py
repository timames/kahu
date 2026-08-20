"""Validation guardrails for the devices API.

These tests exercise the input validation on /api/devices — the index-pattern
allowlist on the OpenSearch endpoint (internal indices must be unreachable),
size/offset caps, and the agent_id/policy_id path patterns — with the Wazuh
clients monkeypatched so no network is touched.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

import kahu.api.devices as devices_mod
from kahu.api.devices import router


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/devices")
    return TestClient(app)


class _FakeIndexer:
    """Records the search call and returns an empty result."""

    last_index: str | None = None
    last_query: dict | None = None

    async def search(self, index: str, query: dict) -> dict:
        _FakeIndexer.last_index = index
        _FakeIndexer.last_query = query
        return {"took": 3, "hits": {"total": {"value": 0}, "hits": []}}


class _FakeWazuhAPI:
    last_path: str | None = None

    async def authenticate(self) -> None:
        pass

    async def api_get(self, path: str, params: dict | None = None) -> dict:
        _FakeWazuhAPI.last_path = path
        return {"data": {"affected_items": [], "total_affected_items": 0}}


# ── OpenSearch index-pattern guard ─────────────────────────


def test_opensearch_rejects_internal_indices(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhIndexerClient", _FakeIndexer)
    client = _make_client()
    for bad in [
        ".opensearch-security*",
        "*",
        "wazuh-alerts-*,.opensearch-security",
        "../wazuh-alerts-*",
        "wazuh-alerts-*/../.opensearch-security",
        ".kibana",
        "security-auditlog-*",
        "wazuh-alerts-* OR *",
    ]:
        resp = client.post("/devices/opensearch", json={"index_pattern": bad, "query": "*"})
        assert resp.status_code in (400, 422), f"pattern accepted: {bad!r}"


def test_opensearch_accepts_wazuh_patterns(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhIndexerClient", _FakeIndexer)
    client = _make_client()
    for good in ["wazuh-alerts-*", "wazuh-alerts-4.x-2026.08.20", "wazuh-archives-*"]:
        resp = client.post("/devices/opensearch", json={"index_pattern": good, "query": "*"})
        assert resp.status_code == 200, f"pattern rejected: {good!r}"
        assert _FakeIndexer.last_index == good


def test_opensearch_query_is_wrapped_not_raw_dsl(monkeypatch):
    """The client's query lands inside a query_string clause, never raw DSL."""
    monkeypatch.setattr(devices_mod, "WazuhIndexerClient", _FakeIndexer)
    client = _make_client()
    resp = client.post(
        "/devices/opensearch",
        json={"index_pattern": "wazuh-alerts-*", "query": "rule.level:>=10"},
    )
    assert resp.status_code == 200
    q = _FakeIndexer.last_query
    assert q is not None
    qs = q["query"]["bool"]["must"][0]["query_string"]
    assert qs["query"] == "rule.level:>=10"
    assert qs["lenient"] is True


def test_opensearch_size_and_offset_caps(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhIndexerClient", _FakeIndexer)
    client = _make_client()
    resp = client.post(
        "/devices/opensearch",
        json={"index_pattern": "wazuh-alerts-*", "query": "*", "size": 500},
    )
    assert resp.status_code == 422
    resp = client.post(
        "/devices/opensearch",
        json={"index_pattern": "wazuh-alerts-*", "query": "*", "offset": 100000},
    )
    assert resp.status_code == 422
    resp = client.post(
        "/devices/opensearch",
        json={"index_pattern": "wazuh-alerts-*", "query": "*", "size": 100, "offset": 9000},
    )
    assert resp.status_code == 200


def test_opensearch_time_range_filter(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhIndexerClient", _FakeIndexer)
    client = _make_client()
    resp = client.post(
        "/devices/opensearch",
        json={
            "index_pattern": "wazuh-alerts-*",
            "query": "*",
            "time_from": "now-1h",
            "time_to": "now",
        },
    )
    assert resp.status_code == 200
    q = _FakeIndexer.last_query
    assert q["query"]["bool"]["filter"] == [
        {"range": {"timestamp": {"gte": "now-1h", "lte": "now"}}}
    ]


# ── SCA path-parameter patterns ────────────────────────────


def test_sca_rejects_bad_agent_ids(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhAPIClient", _FakeWazuhAPI)
    client = _make_client()
    for bad in ["ab", "1", "12", "001x", "..%2f", "001?pretty"]:
        resp = client.get(f"/devices/{bad}/sca")
        # 422 = pattern rejection; 404 = the path segment didn't even route
        assert resp.status_code in (422, 404), f"agent_id accepted: {bad!r}"


def test_sca_accepts_valid_agent_id(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhAPIClient", _FakeWazuhAPI)
    client = _make_client()
    resp = client.get("/devices/001/sca")
    assert resp.status_code == 200
    assert resp.json() == []
    assert _FakeWazuhAPI.last_path == "/sca/001"


def test_sca_checks_rejects_bad_policy_id(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhAPIClient", _FakeWazuhAPI)
    client = _make_client()
    resp = client.get("/devices/001/sca/bad%20policy!/checks")
    assert resp.status_code == 422
    resp = client.get("/devices/001/sca/cis_win2022/checks", params={"result": "DROP TABLE"})
    assert resp.status_code == 422


def test_sca_checks_valid(monkeypatch):
    monkeypatch.setattr(devices_mod, "WazuhAPIClient", _FakeWazuhAPI)
    client = _make_client()
    resp = client.get("/devices/001/sca/cis_win2022/checks", params={"result": "failed"})
    assert resp.status_code == 200
    assert resp.json() == {"checks": [], "total": 0, "offset": 0, "limit": 50}
    assert _FakeWazuhAPI.last_path == "/sca/001/checks/cis_win2022"


# ── Device list degrades gracefully ────────────────────────


def test_devices_list_reports_wazuh_error(monkeypatch):
    class _DownWazuh:
        async def authenticate(self) -> None:
            raise ConnectionError("down")

    monkeypatch.setattr(devices_mod, "WazuhAPIClient", _DownWazuh)
    client = _make_client()
    resp = client.get("/devices")
    assert resp.status_code == 200
    body = resp.json()
    assert body["devices"] == []
    assert body["error"]
