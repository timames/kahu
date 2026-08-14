"""OpenSearch aggregation queries for tuning batch jobs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def build_tuple_agg_query(
    hours_back: float,
    now: datetime | None = None,
) -> dict:
    """Build an OpenSearch date-histogram aggregation query per tuple.

    Returns event counts grouped by (rule_id, source_key, asset_id)
    with hourly buckets over the specified window.
    """
    if now is None:
        now = datetime.now(UTC)
    start = now - timedelta(hours=hours_back)

    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
                ],
                "must_not": [
                    {"term": {"kahu.canary": True}},
                ],
            },
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": 10000},
                "aggs": {
                    "by_source": {
                        "terms": {"field": "agent.name", "size": 1000},
                        "aggs": {
                            "by_asset": {
                                "terms": {"field": "agent.id", "size": 1000},
                                "aggs": {
                                    "hourly": {
                                        "date_histogram": {
                                            "field": "timestamp",
                                            "fixed_interval": "1h",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def parse_tuple_agg_response(response: dict) -> list[dict]:
    """Parse OpenSearch aggregation response into per-tuple records.

    Returns list of:
    {
        "rule_id": str,
        "source_key": str,
        "asset_id": str,
        "total_events": int,
        "hourly_counts": list[int],
        "hour_of_week_indices": list[int],
    }
    """
    results = []
    rule_buckets = response.get("aggregations", {}).get("by_rule", {}).get("buckets", [])

    for rule_b in rule_buckets:
        rule_id = str(rule_b["key"])
        source_buckets = rule_b.get("by_source", {}).get("buckets", [])

        for src_b in source_buckets:
            source_key = str(src_b["key"])
            asset_buckets = src_b.get("by_asset", {}).get("buckets", [])

            for asset_b in asset_buckets:
                asset_id = str(asset_b["key"])
                hourly_buckets = asset_b.get("hourly", {}).get("buckets", [])

                hourly_counts = []
                hour_of_week_indices = []
                total = 0

                for hb in hourly_buckets:
                    count = hb.get("doc_count", 0)
                    hourly_counts.append(count)
                    total += count

                    # Extract hour-of-week from the bucket key timestamp
                    ts_str = hb.get("key_as_string", "")
                    if ts_str:
                        try:
                            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            # Monday=0, hour_of_week = day_of_week * 24 + hour
                            how = dt.weekday() * 24 + dt.hour
                            hour_of_week_indices.append(how)
                        except (ValueError, AttributeError):
                            hour_of_week_indices.append(0)

                results.append(
                    {
                        "rule_id": rule_id,
                        "source_key": source_key,
                        "asset_id": asset_id,
                        "total_events": total,
                        "hourly_counts": hourly_counts,
                        "hour_of_week_indices": hour_of_week_indices,
                    }
                )

    return results


WINDOW_HOURS = {
    "1h": 1.0,
    "24h": 24.0,
    "7d": 168.0,
    "90d": 2160.0,
}
