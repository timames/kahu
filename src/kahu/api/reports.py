"""Reporting API — executive summaries, incident reports, evidence packages."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.services.reporting.generator import (
    generate_evidence_package,
    generate_executive_report,
    generate_incident_report,
)

router = APIRouter()


# ── Executive Report ──


@router.get("/executive")
async def executive_report(
    days: int = Query(7, ge=1, le=90, description="Number of days to cover"),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict:
    """Generate an AI-assisted executive security summary.

    Covers alert volume, severity breakdown, disposition rates,
    top threat sources, and concrete recommendations — written
    in plain language for non-technical leadership.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    return await generate_executive_report(session, since)


# ── Incident Report ──


class IncidentReportRequest(BaseModel):
    alert_ids: list[str] = Field(
        ..., min_length=1, description="Alert UUIDs to include in the incident"
    )
    title: str = Field("", max_length=200, description="Incident title")


@router.post("/incident")
async def incident_report(
    body: IncidentReportRequest,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict:
    """Generate an AI-assisted incident report from a set of related alerts.

    Builds a timeline, identifies IOCs, describes the attack chain,
    and provides response recommendations. Structured for SOC handoff.
    """
    return await generate_incident_report(session, body.alert_ids, body.title)


# ── Evidence Package ──


@router.get("/evidence")
async def evidence_package(
    days: int = Query(30, ge=1, le=365, description="Number of days to cover"),  # noqa: B008
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict:
    """Generate a compliance evidence package.

    Exports all evidence records for the period with hash-chain
    verification, event type breakdown, and an auditor-facing
    narrative summary. Suitable for HIPAA, PCI DSS, and NIST audits.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    return await generate_evidence_package(session, since)
