"""Natural-language investigation API — chat-style log queries."""

from fastapi import APIRouter

router = APIRouter()


@router.post("/query")
async def investigate() -> dict[str, str]:
    return {"status": "not_implemented"}
