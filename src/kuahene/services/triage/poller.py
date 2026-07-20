"""Wazuh alert poller — pulls new alerts from the indexer and feeds them
through the triage pipeline on a schedule."""

import asyncio
import logging
from datetime import datetime, timezone

from kuahene.clients.ollama import OllamaClient
from kuahene.clients.wazuh import WazuhIndexerClient
from kuahene.db import async_session
from kuahene.services.triage.pipeline import run_pipeline_batch

log = logging.getLogger("kuahene.poller")

# Track the last timestamp we've seen so we only fetch new alerts
_last_timestamp: str | None = None


async def poll_once() -> int:
    """Query Wazuh indexer for new alerts and ingest them. Returns count processed."""
    global _last_timestamp

    indexer = WazuhIndexerClient()

    # Build query for alerts newer than our last seen timestamp
    query: dict = {
        "size": 50,
        "sort": [{"timestamp": {"order": "asc"}}],
    }

    if _last_timestamp:
        query["query"] = {
            "range": {"timestamp": {"gt": _last_timestamp}}
        }
    else:
        # First run: get last 5 minutes of alerts
        query["query"] = {
            "range": {"timestamp": {"gte": "now-5m"}}
        }

    try:
        result = await indexer.search(index="wazuh-alerts-*", query=query)
    except Exception as exc:
        log.warning("poller: indexer query failed: %s", exc)
        return 0

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return 0

    # Extract raw alert documents
    raw_alerts = []
    for hit in hits:
        src = hit["_source"]
        raw_alerts.append(src)
        # Track the latest timestamp
        ts = src.get("timestamp")
        if ts:
            _last_timestamp = ts

    # Feed through pipeline
    ollama = OllamaClient()
    async with async_session() as session:
        try:
            _, stats = await run_pipeline_batch(
                raw_alerts=raw_alerts,
                session=session,
                indexer=indexer,
                ollama=ollama,
            )
            log.info(
                "poller: processed=%d filtered=%d triaged=%d persisted=%d errors=%d",
                stats.total, stats.filtered, stats.triaged, stats.persisted, stats.errors,
            )
            return stats.persisted
        except Exception as exc:
            log.error("poller: pipeline batch failed: %s", exc)
            return 0


async def run_poller(interval: float = 15.0) -> None:
    """Run the poller loop forever, polling every `interval` seconds."""
    log.info("poller: starting (interval=%.1fs)", interval)
    while True:
        try:
            await poll_once()
        except Exception as exc:
            log.error("poller: unexpected error: %s", exc)
        await asyncio.sleep(interval)
