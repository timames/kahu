from fastapi import APIRouter

from kahu.api.health import router as health_router
from kahu.api.triage import router as triage_router
from kahu.api.investigation import router as investigation_router
from kahu.api.compliance import router as compliance_router
from kahu.api.briefing import router as briefing_router
from kahu.api.mobile import router as mobile_router
from kahu.api.connectors import router as connectors_router
from kahu.api.vulnerabilities import router as vulns_router
from kahu.api.recon import router as recon_router

router = APIRouter()
router.include_router(health_router, tags=["health"])
router.include_router(briefing_router, tags=["briefing"])
router.include_router(triage_router, prefix="/triage", tags=["triage"])
router.include_router(investigation_router, prefix="/investigation", tags=["investigation"])
router.include_router(compliance_router, prefix="/compliance", tags=["compliance"])
router.include_router(mobile_router, prefix="/m", tags=["mobile"])
router.include_router(connectors_router, prefix="/connectors", tags=["connectors"])
router.include_router(vulns_router, prefix="/vulns", tags=["vulnerabilities"])
router.include_router(recon_router, prefix="/recon", tags=["recon"])
