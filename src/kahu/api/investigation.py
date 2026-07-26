"""Natural-language investigation API — ask questions, get timelines, hunt threats."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.db import get_session
from kahu.services.investigation.query import investigate, get_timeline

router = APIRouter()


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    session_id: str | None = Field(
        None, description="Session ID for multi-turn conversation. Omit to start new."
    )


class ChatResponse(BaseModel):
    response: str
    session_id: str
    context_used: int
    context_sources: dict
    filters_applied: dict
    degraded: bool = False


@router.post("/query", response_model=ChatResponse)
async def investigation_query(
    body: ChatMessage,
    session: AsyncSession = Depends(get_session),
) -> ChatResponse:
    """Ask a natural-language question about alerts, logs, and security posture.

    Supports multi-turn conversations via session_id. Automatically extracts
    IPs, hostnames, rule IDs, severity, and time ranges from the question
    to query both the triaged alert database and Wazuh indexer.
    """
    result = await investigate(body.message, session, body.session_id)
    return ChatResponse(**result)


@router.get("/timeline")
async def investigation_timeline(
    target: str = Query(..., description="Hostname or IP to investigate"),
    hours: int = Query(24, ge=1, le=720, description="How many hours back to look"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Build an event timeline for a specific host or IP.

    Returns all triaged alerts and raw Wazuh logs for the target,
    sorted chronologically.
    """
    return await get_timeline(session, target, hours)
