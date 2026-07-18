"""Connector framework API — source catalog, wizard, and lifecycle."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/catalog")
async def list_connectors() -> dict[str, str]:
    return {"status": "not_implemented"}
