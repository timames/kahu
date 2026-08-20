"""Syslog connector instances get live event counts from the indexer.

Remote-syslog senders (UDM, pfSense) run no Wazuh agent, so their events are
attributed to the manager. The connector card identifies the sender via the
``source_host`` (or pfsense ``host``) config key matched against ``location``
/ ``predecoder.hostname`` in the indexer. These tests pin the query shape and
the host-key resolution with the indexer client monkeypatched.
"""

from types import SimpleNamespace

import kahu.api.connectors as connectors_mod
from kahu.api.connectors import _syslog_host, _syslog_live_stats


class _FakeIndexer:
    last_index: str | None = None
    last_query: dict | None = None

    async def search(self, index: str, query: dict) -> dict:
        _FakeIndexer.last_index = index
        _FakeIndexer.last_query = query
        return {
            "hits": {"total": {"value": 4321}},
            "aggregations": {
                "today": {"doc_count": 167},
                "last_event": {
                    "value": 1786000000000.0,
                    "value_as_string": "2026-08-20T19:44:08.000Z",
                },
            },
        }


async def test_syslog_live_stats_parses_counts(monkeypatch):
    monkeypatch.setattr(connectors_mod, "WazuhIndexerClient", _FakeIndexer)
    today, total, last = await _syslog_live_stats("192.168.131.1")
    assert today == 167
    assert total == 4321
    assert last is not None and last.year == 2026

    q = _FakeIndexer.last_query
    assert _FakeIndexer.last_index == "wazuh-alerts-*"
    assert q["size"] == 0
    shoulds = q["query"]["bool"]["should"]
    assert {"term": {"location": "192.168.131.1"}} in shoulds
    assert {"term": {"predecoder.hostname": "192.168.131.1"}} in shoulds


def _instance(connector_type: str, config: dict) -> SimpleNamespace:
    return SimpleNamespace(connector_type=connector_type, config=config)


def test_syslog_host_resolution():
    # generic_syslog: source_host key
    assert (
        _syslog_host(_instance("generic_syslog", {"source_host": "192.168.131.1"}))
        == "192.168.131.1"
    )
    # no host configured -> no live stats
    assert _syslog_host(_instance("generic_syslog", {"source_name": "hon-udm"})) is None
    # pfsense carries the sender IP as "host"
    assert _syslog_host(_instance("pfsense", {"host": "10.0.0.1"})) == "10.0.0.1"
    # non-syslog connector types never match, even with a host key
    assert _syslog_host(_instance("meraki", {"host": "10.0.0.1"})) is None
    assert _syslog_host(_instance("unknown_type", {"source_host": "x"})) is None
