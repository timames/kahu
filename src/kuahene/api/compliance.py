"""Compliance API — profiles, coverage matrix, evidence packages."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/profiles")
async def list_profiles() -> dict[str, str]:
    return {"status": "not_implemented"}
