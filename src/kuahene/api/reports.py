"""Reporting API — executive, incident, and evidence package generation."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def list_reports() -> dict[str, str]:
    return {"status": "not_implemented"}
