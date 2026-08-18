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

from sqlalchemy import Text, cast, func, or_, select

from kahu.clients.ollama import OllamaClient
from kahu.db import async_session
from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict
from kahu.services.triage.enrichment import enrich_alert_group
from kahu.services.triage.llm_triage import canonical_verdict, run_llm_triage

logger = logging.getLogger(__name__)

REEVAL_INTERVAL_SECONDS = 3600  # 1 hour
REEVAL_BATCH_SIZE = 100
# When acknowledged alerts have NO llm_triage at all (e.g. rows nulled after a
# corruption cleanup), waiting a full hour between batches makes the backlog
# take days to regenerate. While such rows exist, pause only briefly between
# cycles. This is self-limiting: once every acknowledged alert has triage data
# again, pending_regen hits 0 and the loop reverts to the hourly cadence.
REEVAL_BACKLOG_PAUSE_SECONDS = 60
REEVAL_STARTUP_DELAY_SECONDS = 120  # let Ollama preload before the first cycle

_task: asyncio.Task | None = None


def _no_triage():
    """Expression: alert has no LLM triage stored.

    Matches BOTH SQL NULL (raw ``UPDATE ... SET llm_triage=NULL`` cleanups)
    and JSON null (the ORM serialises Python None into a JSON column as the
    JSON literal ``null``, which ``IS NULL`` does not match). Portable across
    Postgres (jsonb::text -> 'null') and SQLite (stored text 'null').
    """
    return or_(Alert.llm_triage.is_(None), cast(Alert.llm_triage, Text) == "null")


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
    """Run re-evaluation forever.

    Normally hourly, but while acknowledged alerts with no llm_triage remain
    (a regeneration backlog) and Ollama is healthy, cycles run back-to-back
    with only a short pause so the backlog drains in hours, not days.
    """
    sleep_seconds = REEVAL_STARTUP_DELAY_SECONDS
    while True:
        try:
            await asyncio.sleep(sleep_seconds)
            stats = await run_reeval_cycle()
            logger.info(
                "Re-evaluation cycle: %d reviewed, %d promoted back to feed, "
                "%d still awaiting triage regeneration",
                stats["reviewed"],
                stats["promoted"],
                stats["pending_regen"],
            )
            # Fast-track only when there is an actual regeneration backlog and
            # the model answered this cycle — never fast-loop against a downed
            # Ollama or when merely re-checking already-triaged dispositions.
            if stats["pending_regen"] > 0 and stats["ollama_healthy"]:
                sleep_seconds = REEVAL_BACKLOG_PAUSE_SECONDS
            else:
                sleep_seconds = REEVAL_INTERVAL_SECONDS
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Re-evaluation cycle failed", exc_info=True)
            sleep_seconds = REEVAL_INTERVAL_SECONDS


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
            # Alerts whose triage was wiped (regeneration backlog) come first;
            # within each group, newest alerts first.
            .order_by(_no_triage().desc(), Alert.created_at.desc())
            .limit(REEVAL_BATCH_SIZE)
        )
        result = await session.execute(stmt)
        rows = result.all()

        if not rows:
            return {"reviewed": 0, "promoted": 0, "pending_regen": 0, "ollama_healthy": True}

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

        # How many acknowledged alerts still have no triage at all — drives the
        # loop's fast/slow cadence. Counted after commit so this batch's writes
        # are reflected.
        pending_stmt = (
            select(func.count())
            .select_from(Alert)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(
                AlertDisposition.verdict.in_(
                    [
                        DispositionVerdict.ACKNOWLEDGED,
                        DispositionVerdict.FALSE_POSITIVE,
                    ]
                )
            )
            .where(_no_triage())
        )
        pending_regen = (await session.execute(pending_stmt)).scalar_one()

    return {
        "reviewed": reviewed,
        "promoted": promoted,
        "pending_regen": pending_regen,
        "ollama_healthy": ollama_healthy,
    }
