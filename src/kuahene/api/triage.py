"""Triage pipeline API — alert queue and disposition endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/queue")
async def get_triage_queue() -> dict[str, str]:
    return {"status": "not_implemented"}
