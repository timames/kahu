"""Canary rule management -- rules excluded from tuning with synthetic event injection."""

from __future__ import annotations

from datetime import UTC, datetime

from kahu_tuning.config import CanaryConfig


def is_canary(rule_id: str, config: CanaryConfig) -> bool:
    """Check if a rule is a canary (excluded from all tuning)."""
    return rule_id in config.canary_rule_ids


def filter_canary_tuples(
    rule_ids: list[str],
    config: CanaryConfig,
) -> list[str]:
    """Return only non-canary rule IDs."""
    return [r for r in rule_ids if r not in config.canary_rule_ids]


def build_canary_event(
    rule_id: str,
    config: CanaryConfig,
) -> dict:
    """Build a synthetic canary event for injection into the test index.

    The event is tagged with kahu.canary=true so it can be identified
    and excluded from real alert processing.
    """
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "rule": {
            "id": rule_id,
            "description": f"Canary test for rule {rule_id}",
            "level": 3,
            "groups": ["canary"],
        },
        "agent": {
            "id": "000",
            "name": "kahu-canary",
        },
        "kahu": {
            "canary": True,
            "inject_timeout": config.inject_timeout_seconds,
        },
        "_index": config.test_index,
    }


async def inject_canary_event(
    rule_id: str,
    config: CanaryConfig,
    indexer_client=None,
) -> dict:
    """Write a synthetic canary event into the test index.

    Args:
        rule_id: The canary rule ID to test.
        config: Canary configuration.
        indexer_client: Optional OpenSearch/Wazuh indexer client for real injection.
            If None, returns the event payload without writing.

    Returns:
        The canary event document.
    """
    event = build_canary_event(rule_id, config)

    if indexer_client is not None:
        await indexer_client.index(
            index=config.test_index,
            body=event,
        )

    return event


async def verify_canary_alert(
    rule_id: str,
    inject_time: datetime,
    config: CanaryConfig,
    indexer_client=None,
) -> bool:
    """Verify that a canary event triggered the expected Wazuh alert.

    Checks the alert index for an alert matching the canary rule_id
    that arrived after inject_time, within the configured timeout window.

    Returns True if the alert was found, False otherwise.
    """
    if indexer_client is None:
        return False

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"rule.id": rule_id}},
                    {"term": {"kahu.canary": True}},
                    {"range": {"timestamp": {"gte": inject_time.isoformat()}}},
                ],
            },
        },
        "size": 1,
    }

    try:
        result = await indexer_client.search(
            index="wazuh-alerts-*",
            query=query,
        )
        hits = result.get("hits", {}).get("total", {})
        total = hits.get("value", 0) if isinstance(hits, dict) else hits
        return total > 0
    except Exception:
        return False
