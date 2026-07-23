"""Greenbone Vulnerability Manager (GVM) client via GSA web API."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

import httpx

from kahu.config import settings

log = logging.getLogger(__name__)


class GreenboneClient:
    """Client for Greenbone Security Assistant (GSA) on immauss/openvas.

    Uses the GMP (Greenbone Management Protocol) XML API via the /gmp endpoint,
    authenticated through the GSA web login (cookie-based).
    """

    def __init__(self) -> None:
        self.base_url = settings.greenbone_url.rstrip("/")
        self.user = settings.greenbone_user
        self.password = settings.greenbone_password
        self._cookies: dict = {}

    # ── Auth ──────────────────────────────────────────────────

    async def authenticate(self) -> None:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.post(
                f"{self.base_url}/auth/login",
                json={"username": self.user, "password": self.password},
            )
            if resp.status_code == 200:
                data = resp.json()
                self._cookies = {"GSAD_SID": data.get("token", "")}
                return

            # Fallback: try form-based login for older GSA versions
            resp = await client.post(
                f"{self.base_url}/login",
                data={"login": self.user, "password": self.password},
                follow_redirects=False,
            )
            self._cookies = dict(resp.cookies)

    async def _ensure_auth(self) -> None:
        if not self._cookies:
            await self.authenticate()

    # ── Health ────────────────────────────────────────────────

    async def health(self) -> dict:
        """Check if GSA is reachable and return version info."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                resp = await client.get(f"{self.base_url}/login")
                if resp.status_code == 200:
                    return {"online": True, "scanner": "greenbone"}
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        return {"online": False, "scanner": "greenbone"}

    # ── GMP XML Commands ─────────────────────────────────────

    async def _gmp_command(self, cmd: str, **attrs) -> ET.Element:
        """Send a GMP command via the /gmp endpoint."""
        await self._ensure_auth()
        params = {"cmd": cmd, **attrs}
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/gmp",
                params=params,
                cookies=self._cookies,
            )
            resp.raise_for_status()
            # GSA returns XML wrapped in JSON or raw XML
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                data = resp.json()
                xml_str = data.get("data", data.get("response", ""))
                if isinstance(xml_str, str) and xml_str.strip().startswith("<"):
                    return ET.fromstring(xml_str)
                return ET.Element("response")
            return ET.fromstring(resp.text)

    async def _omp_request(self, cmd: str, params: dict | None = None) -> dict:
        """Simplified request that tries REST endpoints first, falls back to GMP XML."""
        await self._ensure_auth()
        url_params = {"cmd": cmd}
        if params:
            url_params.update(params)
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/omp",
                params=url_params,
                cookies=self._cookies,
            )
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                if "json" in content_type:
                    return resp.json()
                try:
                    return {"xml": resp.text, "status": "ok"}
                except Exception:
                    return {"status": "error"}
        return {"status": "error"}

    # ── Targets ───────────────────────────────────────────────

    async def get_targets(self) -> list[dict]:
        """List all scan targets."""
        try:
            root = await self._gmp_command("get_targets")
            targets = []
            for t in root.iter("target"):
                targets.append({
                    "id": t.get("id", ""),
                    "name": _text(t, "name"),
                    "hosts": _text(t, "hosts"),
                    "comment": _text(t, "comment"),
                })
            return targets
        except Exception:
            log.debug("get_targets failed", exc_info=True)
            return []

    async def create_target(self, name: str, hosts: str, port_list_id: str = "") -> dict:
        """Create a scan target."""
        attrs = {"name": name, "hosts": hosts}
        if port_list_id:
            attrs["port_list_id"] = port_list_id
        try:
            root = await self._gmp_command("create_target", **attrs)
            return {"id": root.get("id", ""), "status": root.get("status", "")}
        except Exception:
            log.debug("create_target failed", exc_info=True)
            return {}

    # ── Scan Configs ──────────────────────────────────────────

    async def get_scan_configs(self) -> list[dict]:
        """List available scan configurations."""
        try:
            root = await self._gmp_command("get_configs")
            configs = []
            for c in root.iter("config"):
                configs.append({
                    "id": c.get("id", ""),
                    "name": _text(c, "name"),
                    "comment": _text(c, "comment"),
                    "family_count": _text(c, "families/count"),
                    "nvt_count": _text(c, "nvts/count"),
                })
            return configs
        except Exception:
            log.debug("get_scan_configs failed", exc_info=True)
            return []

    # ── Tasks / Scans ─────────────────────────────────────────

    async def get_tasks(self) -> list[dict]:
        """List all scan tasks with status."""
        try:
            root = await self._gmp_command("get_tasks")
            tasks = []
            for t in root.iter("task"):
                last_report = t.find("last_report/report")
                tasks.append({
                    "id": t.get("id", ""),
                    "name": _text(t, "name"),
                    "status": _text(t, "status"),
                    "progress": _text(t, "progress"),
                    "target_id": t.find("target").get("id", "") if t.find("target") is not None else "",
                    "target_name": _text(t, "target/name"),
                    "last_report_id": last_report.get("id", "") if last_report is not None else "",
                    "severity": _text(t, "last_report/report/severity/full/filtered"),
                    "result_count": _text(t, "result_count/full"),
                    "comment": _text(t, "comment"),
                })
            return tasks
        except Exception:
            log.debug("get_tasks failed", exc_info=True)
            return []

    async def create_task(
        self, name: str, target_id: str, scan_config_id: str = ""
    ) -> dict:
        """Create a scan task."""
        attrs = {"name": name, "target_id": target_id}
        if scan_config_id:
            attrs["config_id"] = scan_config_id
        try:
            root = await self._gmp_command("create_task", **attrs)
            return {"id": root.get("id", ""), "status": root.get("status", "")}
        except Exception:
            log.debug("create_task failed", exc_info=True)
            return {}

    async def start_task(self, task_id: str) -> dict:
        """Start a scan task."""
        try:
            root = await self._gmp_command("start_task", task_id=task_id)
            return {"status": root.get("status", ""), "report_id": _text(root, "report_id")}
        except Exception:
            log.debug("start_task failed", exc_info=True)
            return {}

    async def stop_task(self, task_id: str) -> dict:
        """Stop a running scan task."""
        try:
            root = await self._gmp_command("stop_task", task_id=task_id)
            return {"status": root.get("status", "")}
        except Exception:
            log.debug("stop_task failed", exc_info=True)
            return {}

    async def delete_task(self, task_id: str) -> dict:
        """Delete a scan task."""
        try:
            root = await self._gmp_command("delete_task", task_id=task_id)
            return {"status": root.get("status", "")}
        except Exception:
            log.debug("delete_task failed", exc_info=True)
            return {}

    # ── Results ───────────────────────────────────────────────

    async def get_results(self, task_id: str = "", severity_min: float = 0.0) -> list[dict]:
        """Get vulnerability results."""
        attrs = {}
        if task_id:
            attrs["task_id"] = task_id
        try:
            root = await self._gmp_command("get_results", **attrs)
            results = []
            for r in root.iter("result"):
                sev = _float(r, "severity")
                if sev < severity_min:
                    continue
                nvt = r.find("nvt")
                results.append({
                    "id": r.get("id", ""),
                    "name": _text(r, "name"),
                    "host": _text(r, "host"),
                    "port": _text(r, "port"),
                    "severity": sev,
                    "description": _text(r, "description"),
                    "nvt": {
                        "oid": nvt.get("oid", "") if nvt is not None else "",
                        "name": _text(nvt, "name") if nvt is not None else "",
                        "cve": _text(nvt, "cve") if nvt is not None else "",
                        "solution": _text(nvt, "solution") if nvt is not None else "",
                        "solution_type": _text(nvt, "solution_type") if nvt is not None else "",
                        "family": _text(nvt, "family") if nvt is not None else "",
                    },
                    "task_id": r.find("task").get("id", "") if r.find("task") is not None else "",
                    "qod": _text(r, "qod/value"),
                })
            results.sort(key=lambda x: x["severity"], reverse=True)
            return results
        except Exception:
            log.debug("get_results failed", exc_info=True)
            return []

    async def get_reports(self, task_id: str = "") -> list[dict]:
        """List scan reports."""
        attrs = {}
        if task_id:
            attrs["task_id"] = task_id
        try:
            root = await self._gmp_command("get_reports", **attrs)
            reports = []
            for r in root.iter("report"):
                reports.append({
                    "id": r.get("id", ""),
                    "task_id": r.find("task").get("id", "") if r.find("task") is not None else "",
                    "timestamp": _text(r, "timestamp"),
                    "scan_start": _text(r, "scan_start"),
                    "scan_end": _text(r, "scan_end"),
                    "result_count": _text(r, "result_count/full"),
                    "severity": _text(r, "severity/full/filtered"),
                })
            return reports
        except Exception:
            log.debug("get_reports failed", exc_info=True)
            return []

    # ── Port Lists ────────────────────────────────────────────

    async def get_port_lists(self) -> list[dict]:
        """List available port lists."""
        try:
            root = await self._gmp_command("get_port_lists")
            port_lists = []
            for p in root.iter("port_list"):
                port_lists.append({
                    "id": p.get("id", ""),
                    "name": _text(p, "name"),
                    "port_count": _text(p, "port_count/all"),
                    "comment": _text(p, "comment"),
                })
            return port_lists
        except Exception:
            log.debug("get_port_lists failed", exc_info=True)
            return []

    # ── Scanners ──────────────────────────────────────────────

    async def get_scanners(self) -> list[dict]:
        """List configured scanners."""
        try:
            root = await self._gmp_command("get_scanners")
            scanners = []
            for s in root.iter("scanner"):
                scanners.append({
                    "id": s.get("id", ""),
                    "name": _text(s, "name"),
                    "type": _text(s, "type"),
                    "host": _text(s, "host"),
                    "port": _text(s, "port"),
                })
            return scanners
        except Exception:
            log.debug("get_scanners failed", exc_info=True)
            return []


# ── XML helpers ──────────────────────────────────────────────

def _text(elem: ET.Element | None, path: str) -> str:
    """Safely extract text from an XML element path."""
    if elem is None:
        return ""
    el = elem.find(path)
    return (el.text or "").strip() if el is not None else ""


def _float(elem: ET.Element | None, path: str) -> float:
    """Safely extract float from an XML element path."""
    try:
        return float(_text(elem, path))
    except (ValueError, TypeError):
        return 0.0


# Backwards compatibility alias
GreenborneClient = GreenboneClient
