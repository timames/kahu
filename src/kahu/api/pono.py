"""Pono Score API — current score, history, and manual recalculation."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import desc, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.models.pono import PonoSnapshot
from kahu.services.pono import compute_and_persist, pono_loop_running

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ComponentOut(BaseModel):
    name: str
    raw_score: float
    weighted_score: float
    max_points: int
    assessed: bool
    label: str
    evidence_age_days: float
    details: dict | None = None


class SnapshotOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    pono_score: float
    schema_version: str
    components: list[ComponentOut]
    biggest_gain: dict | None = None
    pono_drop: dict | None = None
    trigger: str


class HistoryPoint(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    pono_score: float
    trigger: str


class HistoryResponse(BaseModel):
    snapshots: list[HistoryPoint]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/current", response_model=SnapshotOut | None)
async def get_current_score(
    session: AsyncSession = Depends(get_session),
):
    """Get the most recent Pono Score snapshot."""
    result = await session.execute(
        select(PonoSnapshot)
        .order_by(desc(PonoSnapshot.timestamp))
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()
    if snapshot is None:
        return None
    return _to_out(snapshot)


@router.get("/history", response_model=HistoryResponse)
async def get_score_history(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
):
    """Get Pono Score history for time-series display."""
    stmt = select(PonoSnapshot).order_by(desc(PonoSnapshot.timestamp))

    total = await session.scalar(
        select(func.count()).select_from(stmt.subquery())
    ) or 0

    result = await session.execute(stmt.offset(offset).limit(limit))
    snapshots = result.scalars().all()

    return HistoryResponse(
        snapshots=[
            HistoryPoint(
                id=s.id,
                timestamp=s.timestamp,
                pono_score=s.pono_score,
                trigger=s.trigger,
            )
            for s in snapshots
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
async def get_snapshot(
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Get full detail of a specific snapshot."""
    snapshot = await session.get(PonoSnapshot, snapshot_id)
    if snapshot is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return _to_out(snapshot)


@router.post("/recalculate", response_model=SnapshotOut)
async def recalculate(
    session: AsyncSession = Depends(get_session),
):
    """Trigger an immediate Pono Score recalculation."""
    snapshot = await compute_and_persist(session, trigger="manual")
    return _to_out(snapshot)


@router.get("/status")
async def pono_status():
    """Check if the Pono Score background loop is running."""
    return {
        "loop_running": pono_loop_running(),
    }


def _to_out(snapshot: PonoSnapshot) -> SnapshotOut:
    return SnapshotOut(
        id=snapshot.id,
        timestamp=snapshot.timestamp,
        pono_score=snapshot.pono_score,
        schema_version=snapshot.schema_version,
        components=[ComponentOut(**c) for c in snapshot.components],
        biggest_gain=snapshot.biggest_gain,
        pono_drop=snapshot.pono_drop,
        trigger=snapshot.trigger,
    )
