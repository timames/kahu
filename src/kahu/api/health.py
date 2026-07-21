import httpx
from fastapi import APIRouter

from kahu.config import settings

router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/indexer-health")
async def indexer_health() -> dict:
    """Proxy indexer cluster health so the browser doesn't hit self-signed certs directly."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            r = await client.get(
                f"{settings.wazuh_indexer_url}/_cluster/health",
                auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
            )
            return r.json()
    except Exception:
        return {"status": "unavailable", "cluster_name": "unknown"}
