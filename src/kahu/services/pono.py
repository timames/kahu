"""Pono Score service — computes score from live DB data, persists snapshots."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.config import settings
from kahu.db import async_session
from kahu.models.alerts import Alert, AlertDisposition, Severity
from kahu.models.connectors import ConnectorInstance, ConnectorStatus
from kahu.models.evidence import EvidenceRecord
from kahu.models.pono import PonoSnapshot

from kahu_pono.config import WeightsSchema
from kahu_pono.engine import check_pono_drop, compute_pono_score
from kahu_pono.components.detection import DetectionInput
from kahu_pono.components.tuning import TuningInput
from kahu_pono.components.vulnerability import VulnerabilityInput
from kahu_pono.components.identity import IdentityInput
from kahu_pono.components.response import ResponseInput
from kahu_pono.components.human import HumanInput
from kahu_pono.freshness import evidence_age_days

log = logging.getLogger("kahu.pono")

_schema: WeightsSchema | None = None


def schema_path() -> Path:
    """Resolved location of the Pono weights schema.

    Derived from ``settings.kahu_config_dir`` rather than walked relative to this
    module: the walk only worked from a source checkout, so an installed package
    (the container) silently lost its weights and the score stopped updating.
    """
    return Path(settings.kahu_config_dir) / "weights_schema.json"


def _get_schema() -> WeightsSchema:
    global _schema
    if _schema is None:
        path = schema_path()
        if not path.is_file():
            raise FileNotFoundError(
                f"Pono weights schema not found at {path}. Set KAHU_CONFIG_DIR to the "
                f"directory holding weights_schema.json (repo root 'config/' in dev, "
                f"/app/config in the container)."
            )
        _schema = WeightsSchema.from_file(path)
    return _schema


async def _gather_detection(session: AsyncSession, now: datetime) -> tuple[DetectionInput, float]:
    """Gather detection posture inputs from live DB."""
    from datetime import timedelta

    one_day_ago = now - timedelta(days=1)

    # Sensor health: count distinct agent_names seen in last 24h vs all time
    recent_agents = await session.scalar(
        select(func.count(func.distinct(Alert.agent_name)))
        .where(Alert.created_at >= one_day_ago)
    ) or 0
    total_agents = await session.scalar(
        select(func.count(func.distinct(Alert.agent_name)))
    ) or 0

    # Log source coverage: active connectors vs total
    active_connectors = await session.scalar(
        select(func.count()).where(ConnectorInstance.status == ConnectorStatus.ACTIVE)
    ) or 0
    total_connectors = await session.scalar(
        select(func.count()).select_from(ConnectorInstance)
    ) or 0

    # Latest alert timestamp for update freshness
    latest_alert_ts = await session.scalar(
        select(func.max(Alert.created_at))
    )
    last_update_days = evidence_age_days(latest_alert_ts, now) if latest_alert_ts else 30.0

    # Latest evidence for this component
    latest_evidence = await session.scalar(
        select(func.max(EvidenceRecord.timestamp))
    )
    age = evidence_age_days(latest_evidence, now) if latest_evidence else 0.0

    return DetectionInput(
        last_update_days=last_update_days,
        sensors_total=max(total_agents, 1),
        sensors_healthy=recent_agents,
        expected_sources=max(total_connectors, 1),
        active_sources=active_connectors,
    ), age


async def _gather_response(session: AsyncSession, now: datetime) -> tuple[ResponseInput, float]:
    """Gather response readiness inputs from disposition data."""
    from datetime import timedelta
    from sqlalchemy import extract

    ack_sla_minutes = 15.0

    # Join alerts to dispositions for actual ACK times
    ack_query = (
        select(
            AlertDisposition.created_at.label("disp_at"),
            Alert.created_at.label("alert_at"),
        )
        .join(Alert, AlertDisposition.alert_id == Alert.id)
        .where(Alert.severity.in_([Severity.CRITICAL, Severity.HIGH]))
    )
    result = await session.execute(ack_query)
    rows = result.all()

    if rows:
        ack_minutes_list = []
        cases_in_sla = 0
        for row in rows:
            delta = (row.disp_at - row.alert_at).total_seconds() / 60.0
            ack_minutes_list.append(delta)
            if delta <= ack_sla_minutes:
                cases_in_sla += 1

        ack_minutes_list.sort()
        mid = len(ack_minutes_list) // 2
        median_ack = (
            ack_minutes_list[mid]
            if len(ack_minutes_list) % 2
            else (ack_minutes_list[mid - 1] + ack_minutes_list[mid]) / 2.0
        )
    else:
        median_ack = 0.0
        cases_in_sla = 0

    # Total cases needing response (critical + high alerts)
    total_needing = await session.scalar(
        select(func.count()).where(
            Alert.severity.in_([Severity.CRITICAL, Severity.HIGH])
        )
    ) or 0

    # Auto-disposition (playbook) stats from pipeline_provenance
    auto_disposed = await session.scalar(
        select(func.count()).where(
            Alert.pipeline_provenance["auto_disposed"].as_string() == "true"
        )
    ) or 0
    total_alerts = await session.scalar(
        select(func.count()).select_from(Alert)
    ) or 0

    latest_disposition = await session.scalar(
        select(func.max(AlertDisposition.created_at))
    )
    age = evidence_age_days(latest_disposition, now) if latest_disposition else 0.0

    return ResponseInput(
        median_ack_minutes=median_ack,
        ack_sla_minutes=ack_sla_minutes,
        cases_in_sla=cases_in_sla,
        cases_total=max(total_needing, 1),
        playbook_successes=auto_disposed,
        playbook_executions=total_alerts,
    ), age


async def _gather_evidence_ages(session: AsyncSession, now: datetime) -> dict[str, float]:
    """Get evidence age per component from the evidence store."""
    # Use latest evidence timestamp as a general freshness indicator
    latest = await session.scalar(
        select(func.max(EvidenceRecord.timestamp))
    )
    default_age = evidence_age_days(latest, now) if latest else 0.0
    return {
        "detection_posture": default_age,
        "tuning_hygiene": default_age,
        "vulnerability_posture": default_age,
        "identity_access": default_age,
        "response_readiness": default_age,
        "human_layer": default_age,
    }


async def gather_inputs(session: AsyncSession) -> tuple[dict, dict[str, float]]:
    """Gather all component inputs from the live database.

    Returns (inputs dict, evidence_ages dict).
    Components without live data sources use data_available=False.
    """
    now = datetime.now(timezone.utc)

    detection_input, detection_age = await _gather_detection(session, now)
    response_input, response_age = await _gather_response(session, now)
    evidence_ages = await _gather_evidence_ages(session, now)

    # Override with component-specific ages where we have them
    evidence_ages["detection_posture"] = detection_age
    evidence_ages["response_readiness"] = response_age

    inputs = {
        "detection_posture": detection_input,
        "response_readiness": response_input,
        # These components don't have live data sources wired up yet
        "tuning_hygiene": TuningInput(data_available=False),
        "vulnerability_posture": VulnerabilityInput(data_available=False),
        "identity_access": IdentityInput(data_available=False),
        "human_layer": HumanInput(data_available=False),
    }

    return inputs, evidence_ages


async def compute_and_persist(
    session: AsyncSession,
    trigger: str = "scheduled",
) -> PonoSnapshot:
    """Compute the Pono Score from live data and persist a snapshot."""
    schema = _get_schema()
    inputs, evidence_ages = await gather_inputs(session)

    result = compute_pono_score(schema, inputs, evidence_ages)

    # Check for drop vs previous snapshot
    prev = await session.scalar(
        select(PonoSnapshot.pono_score)
        .order_by(desc(PonoSnapshot.timestamp))
        .limit(1)
    )
    drop = None
    if prev is not None:
        drop = check_pono_drop(result.pono_score, prev, schema.pono_drop_threshold)

    snapshot = PonoSnapshot(
        pono_score=round(result.pono_score, 2),
        schema_version=result.schema_version,
        components=[
            {
                "name": c.name,
                "raw_score": round(c.raw_score, 4),
                "weighted_score": round(c.weighted_score, 2),
                "max_points": c.max_points,
                "assessed": c.assessed,
                "label": c.label,
                "evidence_age_days": round(c.evidence_age_days, 1),
                "details": c.details,
            }
            for c in result.components
        ],
        biggest_gain=result.biggest_gain,
        pono_drop=drop,
        trigger=trigger,
    )
    session.add(snapshot)
    await session.commit()
    await session.refresh(snapshot)

    if drop:
        log.warning(
            "pono: score dropped %.1f points (%.1f → %.1f)",
            drop["drop"], drop["previous_score"], drop["current_score"],
        )

    log.info("pono: snapshot persisted score=%.1f trigger=%s", snapshot.pono_score, trigger)
    return snapshot


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

_pono_task: asyncio.Task | None = None


def pono_loop_running() -> bool:
    return _pono_task is not None and not _pono_task.done()


async def run_pono_loop(interval: float = 300.0) -> None:
    """Recalculate Pono Score every `interval` seconds (default 5 min)."""
    global _pono_task
    _pono_task = asyncio.current_task()
    log.info("pono: background loop starting (interval=%.0fs)", interval)
    while True:
        try:
            async with async_session() as session:
                await compute_and_persist(session, trigger="scheduled")
        except asyncio.CancelledError:
            log.info("pono: background loop stopped")
            break
        except Exception as exc:
            log.error("pono: background computation failed: %s", exc)
        await asyncio.sleep(interval)
