"""Vulnerability scanner API — scan management, results, and dashboard."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from kahu.clients.greenbone import GreenboneClient

router = APIRouter()
log = logging.getLogger(__name__)


# ── Schemas ────────────────────────────────────────────────


class ScanTargetCreate(BaseModel):
    name: str
    hosts: str  # comma-separated IPs / CIDRs
    port_list_id: str = ""


class ScanTaskCreate(BaseModel):
    name: str
    target_id: str
    scan_config_id: str = ""


class VulnSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    scanner_online: bool = False
    tasks_running: int = 0
    tasks_total: int = 0


# ── Dashboard ─────────────────────────────────────────────


@router.get("/summary", response_model=VulnSummary)
async def vulnerability_summary():
    """High-level vulnerability counts for the dashboard."""
    gvm = GreenboneClient()

    health = await gvm.health()
    if not health["online"]:
        return VulnSummary(scanner_online=False)

    try:
        results = await gvm.get_results()
        tasks = await gvm.get_tasks()
    except Exception:
        log.exception("Failed to fetch vulnerability summary")
        return VulnSummary(scanner_online=True)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = _classify_severity(r.get("severity", 0))
        counts[sev] += 1

    running = sum(1 for t in tasks if t.get("status") in ("Running", "Requested"))

    return VulnSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        total=len(results),
        scanner_online=True,
        tasks_running=running,
        tasks_total=len(tasks),
    )


# ── Targets ───────────────────────────────────────────────


@router.get("/targets")
async def list_targets():
    """List all scan targets."""
    gvm = GreenboneClient()
    try:
        targets = await gvm.get_targets()
    except Exception:
        log.exception("Failed to list targets")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"targets": targets}


@router.post("/targets", status_code=201)
async def create_target(body: ScanTargetCreate):
    """Create a new scan target."""
    gvm = GreenboneClient()
    try:
        result = await gvm.create_target(
            name=body.name,
            hosts=body.hosts,
            port_list_id=body.port_list_id,
        )
    except Exception:
        log.exception("Failed to create target")
        raise HTTPException(502, "Scanner unavailable") from None
    return result


# ── Scan Configs ──────────────────────────────────────────


@router.get("/configs")
async def list_scan_configs():
    """List available scan configurations (Full & Fast, Discovery, etc.)."""
    gvm = GreenboneClient()
    try:
        configs = await gvm.get_scan_configs()
    except Exception:
        log.exception("Failed to list scan configs")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"configs": configs}


@router.get("/port-lists")
async def list_port_lists():
    """List available port lists."""
    gvm = GreenboneClient()
    try:
        port_lists = await gvm.get_port_lists()
    except Exception:
        log.exception("Failed to list port lists")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"port_lists": port_lists}


@router.get("/scanners")
async def list_scanners():
    """List configured scanners (OpenVAS, CVE, etc.)."""
    gvm = GreenboneClient()
    try:
        scanners = await gvm.get_scanners()
    except Exception:
        log.exception("Failed to list scanners")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"scanners": scanners}


# ── Scans / Tasks ────────────────────────────────────────


@router.get("/scans")
async def list_scans():
    """List all scan tasks with status."""
    gvm = GreenboneClient()
    try:
        tasks = await gvm.get_tasks()
    except Exception:
        log.exception("Failed to list scans")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"scans": tasks}


@router.post("/scans", status_code=201)
async def create_scan(body: ScanTaskCreate):
    """Create and start a new scan."""
    gvm = GreenboneClient()
    try:
        task = await gvm.create_task(
            name=body.name,
            target_id=body.target_id,
            scan_config_id=body.scan_config_id,
        )
        task_id = task.get("id", "")
        if task_id:
            await gvm.start_task(task_id)
            task["status"] = "Requested"
    except Exception:
        log.exception("Failed to create scan")
        raise HTTPException(502, "Scanner unavailable") from None
    return task


@router.post("/scans/{task_id}/start")
async def start_scan(task_id: str):
    """Start an existing scan task."""
    gvm = GreenboneClient()
    try:
        result = await gvm.start_task(task_id)
    except Exception:
        log.exception("Failed to start scan")
        raise HTTPException(502, "Scanner unavailable") from None
    return result


@router.post("/scans/{task_id}/stop")
async def stop_scan(task_id: str):
    """Stop a running scan task."""
    gvm = GreenboneClient()
    try:
        result = await gvm.stop_task(task_id)
    except Exception:
        log.exception("Failed to stop scan")
        raise HTTPException(502, "Scanner unavailable") from None
    return result


@router.delete("/scans/{task_id}")
async def delete_scan(task_id: str):
    """Delete a scan task."""
    gvm = GreenboneClient()
    try:
        result = await gvm.delete_task(task_id)
    except Exception:
        log.exception("Failed to delete scan")
        raise HTTPException(502, "Scanner unavailable") from None
    return result


@router.get("/scans/{task_id}")
async def get_scan(task_id: str):
    """Get scan details and progress."""
    gvm = GreenboneClient()
    try:
        tasks = await gvm.get_tasks()
        task = next((t for t in tasks if t["id"] == task_id), None)
        if not task:
            raise HTTPException(404, "Scan not found")
    except HTTPException:
        raise
    except Exception:
        log.exception("Failed to get scan details")
        raise HTTPException(502, "Scanner unavailable") from None
    return task


# ── Results / Reports ────────────────────────────────────


@router.get("/results")
async def list_results(task_id: str = "", severity_min: float = 0.0):
    """Get vulnerability findings, optionally filtered."""
    gvm = GreenboneClient()
    try:
        results = await gvm.get_results(task_id=task_id, severity_min=severity_min)
    except Exception:
        log.exception("Failed to fetch results")
        raise HTTPException(502, "Scanner unavailable") from None

    findings = []
    for r in results:
        sev_score = r.get("severity", 0)
        nvt = r.get("nvt", {})
        findings.append(
            {
                "id": r.get("id", ""),
                "name": r.get("name", "Unknown"),
                "host": r.get("host", ""),
                "port": r.get("port", ""),
                "severity": sev_score,
                "severity_label": _classify_severity(sev_score),
                "cve": nvt.get("cve", ""),
                "family": nvt.get("family", ""),
                "description": r.get("description", ""),
                "solution": nvt.get("solution", ""),
                "solution_type": nvt.get("solution_type", ""),
                "qod": r.get("qod", ""),
                "task_id": r.get("task_id", ""),
            }
        )

    findings.sort(key=lambda f: f["severity"], reverse=True)
    return {"findings": findings, "total": len(findings)}


@router.get("/reports")
async def list_reports(task_id: str = ""):
    """List scan reports."""
    gvm = GreenboneClient()
    try:
        reports = await gvm.get_reports(task_id=task_id)
    except Exception:
        log.exception("Failed to fetch reports")
        raise HTTPException(502, "Scanner unavailable") from None
    return {"reports": reports}


# ── Health ────────────────────────────────────────────────


@router.get("/health")
async def scanner_health():
    """Check if the vulnerability scanner is reachable."""
    gvm = GreenboneClient()
    return await gvm.health()


# ── Helpers ───────────────────────────────────────────────


def _classify_severity(score: float | int | str) -> str:
    """CVSS score -> severity label."""
    try:
        s = float(score)
    except (ValueError, TypeError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"
