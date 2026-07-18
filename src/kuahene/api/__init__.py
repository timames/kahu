from fastapi import APIRouter

from kuahene.api.health import router as health_router
from kuahene.api.triage import router as triage_router
from kuahene.api.investigation import router as investigation_router
from kuahene.api.reports import router as reports_router
from kuahene.api.compliance import router as compliance_router
from kuahene.api.connectors import router as connectors_router

router = APIRouter()
router.include_router(health_router, tags=["health"])
router.include_router(triage_router, prefix="/triage", tags=["triage"])
router.include_router(investigation_router, prefix="/investigation", tags=["investigation"])
router.include_router(reports_router, prefix="/reports", tags=["reports"])
router.include_router(compliance_router, prefix="/compliance", tags=["compliance"])
router.include_router(connectors_router, prefix="/connectors", tags=["connectors"])
