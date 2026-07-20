from fastapi import APIRouter

from kuahene.api.health import router as health_router
from kuahene.api.triage import router as triage_router
from kuahene.api.investigation import router as investigation_router
from kuahene.api.reports import router as reports_router
from kuahene.api.compliance import router as compliance_router
from kuahene.api.connectors import router as connectors_router
from kuahene.api.vulnerabilities import router as vulnerabilities_router
from kuahene.api.briefing import router as briefing_router
from kuahene.api.agents import router as agents_router
from kuahene.api.config_plane import router as config_plane_router

router = APIRouter()
router.include_router(health_router, tags=["health"])
router.include_router(briefing_router, tags=["briefing"])
router.include_router(triage_router, prefix="/triage", tags=["triage"])
router.include_router(investigation_router, prefix="/investigation", tags=["investigation"])
router.include_router(reports_router, prefix="/reports", tags=["reports"])
router.include_router(compliance_router, prefix="/compliance", tags=["compliance"])
router.include_router(connectors_router, prefix="/connectors", tags=["connectors"])
router.include_router(vulnerabilities_router, prefix="/vulnerabilities", tags=["vulnerabilities"])
router.include_router(agents_router, prefix="/agents", tags=["agents"])
router.include_router(config_plane_router, prefix="/config-plane", tags=["config-plane"])
