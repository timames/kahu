"""Vulnerability scanner API — scan management, results, and dashboard."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from kahu.clients.greenbone import GreenborneClient

router = APIRouter()
log = logging.getLogger(__name__)


# ── Schemas ────────────────────────────────────────────────


class ScanTargetCreate(BaseModel):
    name: str
    hosts: str  # comma-separated IPs / CIDRs


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
    gvm = GreenborneClient()

    online = await gvm.health()
    if not online:
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
    gvm = GreenborneClient()
    try:
        targets = await gvm.get_targets()
    except Exception:
        log.exception("Failed to list targets")
        raise HTTPException(502, "Scanner unavailable")
    return {"targets": targets}


@router.post("/targets", status_code=201)
async def create_target(body: ScanTargetCreate):
    """Create a new scan target."""
    gvm = GreenborneClient()
    try:
        result = await gvm.create_target(name=body.name, hosts=body.hosts)
    except Exception:
        log.exception("Failed to create target")
        raise HTTPException(502, "Scanner unavailable")
    return result


# ── Scans ─────────────────────────────────────────────────


@router.get("/scans")
async def list_scans():
    """List all scan tasks with status."""
    gvm = GreenborneClient()
    try:
        tasks = await gvm.get_tasks()
    except Exception:
        log.exception("Failed to list scans")
        raise HTTPException(502, "Scanner unavailable")
    return {"scans": tasks}


@router.post("/scans", status_code=201)
async def create_scan(body: ScanTaskCreate):
    """Create and start a new scan."""
    gvm = GreenborneClient()
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
        raise HTTPException(502, "Scanner unavailable")
    return task


@router.post("/scans/{task_id}/start")
async def start_scan(task_id: str):
    """Start an existing scan task."""
    gvm = GreenborneClient()
    try:
        result = await gvm.start_task(task_id)
    except Exception:
        log.exception("Failed to start scan")
        raise HTTPException(502, "Scanner unavailable")
    return result


@router.get("/scans/{task_id}")
async def get_scan(task_id: str):
    """Get scan details and progress."""
    gvm = GreenborneClient()
    try:
        task = await gvm.get_task(task_id)
    except Exception:
        log.exception("Failed to get scan details")
        raise HTTPException(502, "Scanner unavailable")
    return task


# ── Results ───────────────────────────────────────────────


@router.get("/results")
async def list_results(task_id: str = "", severity_min: float = 0.0):
    """Get vulnerability findings, optionally filtered."""
    gvm = GreenborneClient()
    try:
        results = await gvm.get_results(task_id=task_id, severity_min=severity_min)
    except Exception:
        log.exception("Failed to fetch results")
        raise HTTPException(502, "Scanner unavailable")

    # Normalize and enrich each result
    findings = []
    for r in results:
        sev_score = r.get("severity", 0)
        findings.append({
            "id": r.get("id", ""),
            "name": r.get("name", "Unknown"),
            "host": r.get("host", {}).get("hostname", r.get("host", "")),
            "port": r.get("port", ""),
            "severity": sev_score,
            "severity_label": _classify_severity(sev_score),
            "cve": r.get("nvt", {}).get("cve", ""),
            "description": r.get("description", ""),
            "solution": r.get("nvt", {}).get("solution", ""),
            "task_id": r.get("task", {}).get("id", ""),
        })

    # Sort by severity descending
    findings.sort(key=lambda f: f["severity"], reverse=True)
    return {"findings": findings, "total": len(findings)}


# ── Health ────────────────────────────────────────────────


@router.get("/health")
async def scanner_health():
    """Check if the vulnerability scanner is reachable."""
    gvm = GreenborneClient()
    online = await gvm.health()
    return {"online": online, "scanner": "greenbone"}


# ── Helpers ───────────────────────────────────────────────


def _classify_severity(score: float | int | str) -> str:
    """CVSS score → severity label."""
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
