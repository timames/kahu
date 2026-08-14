"""Validation API — trigger rounds, view results, check for drift."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.models.validation import ValidationRound, ValidationVerdict
from kahu.services.validation import get_latest_round, get_round_samples, run_validation_round

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SampleOut(BaseModel):
    id: uuid.UUID
    agent_id: str
    agent_name: str
    scheduled_at: datetime
    completed_at: datetime | None
    verdict: str
    checks: dict | None
    findings: list | None
    score_at_sample: float | None


class RoundOut(BaseModel):
    id: uuid.UUID
    started_at: datetime
    completed_at: datetime | None
    sample_size: int
    fleet_size: int
    samples_completed: int
    samples_passed: int
    samples_failed: int
    samples_unreachable: int
    pono_score_at_start: float
    validation_rate: float | None
    drift_detected: bool | None
    summary: dict | None


class RoundListItem(BaseModel):
    id: uuid.UUID
    started_at: datetime
    sample_size: int
    fleet_size: int
    validation_rate: float | None
    drift_detected: bool | None
    pono_score_at_start: float


class RoundListResponse(BaseModel):
    rounds: list[RoundListItem]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/rounds", response_model=RoundOut)
async def trigger_validation_round(
    sample_size: int = Query(13, ge=1, le=100),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
):
    """Trigger a validation round — randomly sample endpoints and check them."""
    vr = await run_validation_round(session, sample_size=sample_size)
    return _round_to_out(vr)


@router.get("/rounds", response_model=RoundListResponse)
async def list_rounds(
    offset: int = Query(0, ge=0),  # noqa: B008
    limit: int = Query(20, ge=1, le=100),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
):
    """List validation rounds, most recent first."""
    stmt = select(ValidationRound).order_by(desc(ValidationRound.started_at))
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    result = await session.execute(stmt.offset(offset).limit(limit))
    rounds = result.scalars().all()
    return RoundListResponse(
        rounds=[
            RoundListItem(
                id=r.id,
                started_at=r.started_at,
                sample_size=r.sample_size,
                fleet_size=r.fleet_size,
                validation_rate=r.validation_rate,
                drift_detected=r.drift_detected,
                pono_score_at_start=r.pono_score_at_start,
            )
            for r in rounds
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/rounds/latest", response_model=RoundOut | None)
async def latest_round(session: AsyncSession = Depends(get_session)):  # noqa: B008
    """Get the most recent validation round."""
    vr = await get_latest_round(session)
    if vr is None:
        return None
    return _round_to_out(vr)


@router.get("/rounds/{round_id}", response_model=RoundOut)
async def get_round(
    round_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
):
    """Get full detail of a validation round."""
    vr = await session.get(ValidationRound, round_id)
    if vr is None:
        raise HTTPException(status_code=404, detail="Validation round not found")
    return _round_to_out(vr)


@router.get("/rounds/{round_id}/samples", response_model=list[SampleOut])
async def get_samples(
    round_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),  # noqa: B008
):
    """Get all endpoint samples for a validation round."""
    samples = await get_round_samples(session, str(round_id))
    return [
        SampleOut(
            id=s.id,
            agent_id=s.agent_id,
            agent_name=s.agent_name,
            scheduled_at=s.scheduled_at,
            completed_at=s.completed_at,
            verdict=s.verdict.value if isinstance(s.verdict, ValidationVerdict) else s.verdict,
            checks=s.checks,
            findings=s.findings,
            score_at_sample=s.score_at_sample,
        )
        for s in samples
    ]


@router.get("/drift")
async def check_drift(session: AsyncSession = Depends(get_session)):  # noqa: B008
    """Quick check: has the latest validation round detected drift?"""
    vr = await get_latest_round(session)
    if vr is None:
        return {"has_validation": False, "drift_detected": None}
    return {
        "has_validation": True,
        "drift_detected": vr.drift_detected,
        "validation_rate": vr.validation_rate,
        "pono_score_at_start": vr.pono_score_at_start,
        "round_id": str(vr.id),
        "round_date": vr.started_at.isoformat(),
    }


def _round_to_out(vr: ValidationRound) -> RoundOut:
    return RoundOut(
        id=vr.id,
        started_at=vr.started_at,
        completed_at=vr.completed_at,
        sample_size=vr.sample_size,
        fleet_size=vr.fleet_size,
        samples_completed=vr.samples_completed,
        samples_passed=vr.samples_passed,
        samples_failed=vr.samples_failed,
        samples_unreachable=vr.samples_unreachable,
        pono_score_at_start=vr.pono_score_at_start,
        validation_rate=vr.validation_rate,
        drift_detected=vr.drift_detected,
        summary=vr.summary,
    )
