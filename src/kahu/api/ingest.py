"""Machine-to-machine alert ingestion — token-authenticated, no user JWT.

The rest of the triage router is mounted behind ``Depends(get_current_user)``,
but external forwarders (the demo generator, a syslog-to-webhook bridge, a
future SIEM connector) have no interactive login. They authenticate with a
static shared secret carried in the ``X-Ingest-Token`` header, checked against
``settings.ingest_token``.

This router is mounted **publicly** under the same ``/triage`` prefix as the
protected router; only this single ``POST /ingest`` route lives here, so the
JWT-protected routes are unaffected. If ``ingest_token`` is unset the route
rejects everything — ingestion must be explicitly enabled.
"""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.clients.ollama import OllamaClient
from kahu.clients.wazuh import WazuhIndexerClient
from kahu.config import settings
from kahu.db import get_session
from kahu.schemas.triage import PipelineBatchRequest, PipelineBatchResponse
from kahu.services.triage.pipeline import run_pipeline_batch

router = APIRouter()


async def verify_ingest_token(x_ingest_token: str | None = Header(default=None)) -> None:
    """Reject requests without a valid ingest token.

    Uses a constant-time comparison and refuses outright when no token is
    configured, so ingestion can never be left open by accident.
    """
    expected = settings.ingest_token
    if not expected or not x_ingest_token or not hmac.compare_digest(x_ingest_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing ingest token",
        )


@router.post(
    "/ingest",
    response_model=PipelineBatchResponse,
    dependencies=[Depends(verify_ingest_token)],
)
async def ingest_alerts(
    body: PipelineBatchRequest,
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> PipelineBatchResponse:
    """Ingest a batch of raw Wazuh alerts through the triage pipeline."""
    indexer = WazuhIndexerClient()
    ollama = OllamaClient()

    _, stats = await run_pipeline_batch(
        raw_alerts=body.alerts,
        session=session,
        indexer=indexer,
        ollama=ollama,
    )

    return PipelineBatchResponse(
        processed=stats.total,
        filtered=stats.filtered,
        triaged=stats.triaged,
        persisted=stats.persisted,
        errors=stats.errors,
    )
