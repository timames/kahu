from fastapi import APIRouter, Depends

from kahu.api.agents import router as agents_router
from kahu.api.arsenal import router as arsenal_router
from kahu.api.auth import router as auth_router
from kahu.api.briefing import router as briefing_router
from kahu.api.compliance import router as compliance_router
from kahu.api.connectors import router as connectors_router
from kahu.api.deps import get_current_user
from kahu.api.health import router as health_router
from kahu.api.investigation import router as investigation_router
from kahu.api.mobile import router as mobile_router
from kahu.api.pono import router as pono_router
from kahu.api.recon import router as recon_router
from kahu.api.reports import router as reports_router
from kahu.api.triage import router as triage_router
from kahu.api.validation import router as validation_router
from kahu.api.vulnerabilities import router as vulns_router

router = APIRouter()

# Public routes — no auth required
router.include_router(health_router, tags=["health"])
router.include_router(auth_router, prefix="/auth", tags=["auth"])

# Protected routes — require valid JWT
_auth = [Depends(get_current_user)]  # noqa: B008
router.include_router(briefing_router, tags=["briefing"], dependencies=_auth)
router.include_router(triage_router, prefix="/triage", tags=["triage"], dependencies=_auth)
router.include_router(
    investigation_router, prefix="/investigation", tags=["investigation"], dependencies=_auth
)
router.include_router(
    compliance_router, prefix="/compliance", tags=["compliance"], dependencies=_auth
)
router.include_router(reports_router, prefix="/reports", tags=["reports"], dependencies=_auth)
router.include_router(mobile_router, prefix="/m", tags=["mobile"], dependencies=_auth)
router.include_router(
    connectors_router, prefix="/connectors", tags=["connectors"], dependencies=_auth
)
router.include_router(vulns_router, prefix="/vulns", tags=["vulnerabilities"], dependencies=_auth)
router.include_router(recon_router, prefix="/recon", tags=["recon"], dependencies=_auth)
router.include_router(arsenal_router, prefix="/arsenal", tags=["arsenal"], dependencies=_auth)
router.include_router(pono_router, prefix="/pono", tags=["pono"], dependencies=_auth)
router.include_router(
    validation_router, prefix="/validation", tags=["validation"], dependencies=_auth
)
router.include_router(agents_router, prefix="/agents", tags=["agents"], dependencies=_auth)
