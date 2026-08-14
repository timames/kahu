"""Hourly re-evaluation of acknowledged alerts.

Acknowledged alerts are not permanently dismissed — they are saved and
re-evaluated by the AI every hour. If threat intelligence, disposition
history, or new correlated events change the picture, the alert gets
promoted back to the feed for human review.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from kahu.clients.ollama import OllamaClient
from kahu.db import async_session
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict
from kahu.services.triage.enrichment import enrich_alert_group
from kahu.services.triage.llm_triage import canonical_verdict, run_llm_triage

logger = logging.getLogger(__name__)

REEVAL_INTERVAL_SECONDS = 3600  # 1 hour
REEVAL_BATCH_SIZE = 100

_task: asyncio.Task | None = None


async def start_reeval_loop():
    """Start the background re-evaluation loop."""
    global _task
    if _task is not None:
        return
    _task = asyncio.create_task(_reeval_loop())
    logger.info(
        "Started acknowledged alert re-evaluation loop (every %ds)", REEVAL_INTERVAL_SECONDS
    )


async def stop_reeval_loop():
    """Stop the background re-evaluation loop."""
    global _task
    if _task is not None:
        _task.cancel()
        _task = None
        logger.info("Stopped re-evaluation loop")


async def _reeval_loop():
    """Run re-evaluation forever on the configured interval."""
    while True:
        try:
            await asyncio.sleep(REEVAL_INTERVAL_SECONDS)
            stats = await run_reeval_cycle()
            logger.info(
                "Re-evaluation cycle: %d reviewed, %d promoted back to feed",
                stats["reviewed"],
                stats["promoted"],
            )
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Re-evaluation cycle failed", exc_info=True)


async def run_reeval_cycle() -> dict:
    """Re-evaluate acknowledged alerts. Returns stats dict.

    For each acknowledged alert:
    1. Re-enrich with current context (new related events, updated history)
    2. Run LLM triage with fresh data
    3. If verdict changes to true_positive or escalate → delete disposition
       so the alert reappears in the feed
    4. If still benign → update the disposition timestamp (keeps it fresh)
    """
    promoted = 0
    reviewed = 0

    async with async_session() as session:
        # Get acknowledged alerts (both legacy false_positive and new acknowledged)
        stmt = (
            select(Alert, AlertDisposition)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(
                AlertDisposition.verdict.in_(
                    [
                        DispositionVerdict.ACKNOWLEDGED,
                        DispositionVerdict.FALSE_POSITIVE,
                    ]
                )
            )
            # Only re-evaluate if last check was > 1 hour ago
            .where(
                AlertDisposition.updated_at
                < datetime.now(UTC) - timedelta(seconds=REEVAL_INTERVAL_SECONDS)
            )
            .order_by(Alert.created_at.desc())
            .limit(REEVAL_BATCH_SIZE)
        )
        result = await session.execute(stmt)
        rows = result.all()

        if not rows:
            return {"reviewed": 0, "promoted": 0}

        ollama = OllamaClient()
        ollama_healthy = await ollama.health()

        for alert, disposition in rows:
            reviewed += 1
            raw = alert.raw_event or {}

            try:
                # Re-enrich with fresh context
                enriched = await enrich_alert_group(
                    alert=raw,
                    session=session,
                    indexer=None,  # Skip indexer for background task
                )

                if ollama_healthy:
                    # Re-run LLM triage
                    llm_result = await run_llm_triage(enriched, ollama)
                    # Already canonical from _parse_llm_response; normalise again
                    # so a hand-built or legacy payload can't slip through.
                    verdict = canonical_verdict(llm_result.get("recommended_verdict"))

                    if verdict in ("true_positive", "escalate"):
                        # Alert needs human attention again — remove disposition
                        await session.delete(disposition)
                        # Update LLM triage data on the alert
                        alert.llm_triage = llm_result
                        promoted += 1
                        logger.info(
                            "Re-eval promoted alert %s back to feed (new verdict: %s)",
                            alert.id,
                            verdict,
                        )
                    else:
                        # Still benign — touch the timestamp so we don't re-check immediately
                        disposition.updated_at = datetime.now(UTC)
                        # Update LLM output with latest assessment
                        alert.llm_triage = llm_result
                else:
                    # Ollama down — just touch timestamp to avoid retry storm
                    disposition.updated_at = datetime.now(UTC)

            except Exception:
                logger.warning("Failed to re-evaluate alert %s", alert.id, exc_info=True)
                continue

        await session.commit()

    return {"reviewed": reviewed, "promoted": promoted}
