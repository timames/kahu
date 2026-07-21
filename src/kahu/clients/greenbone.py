"""Greenbone Vulnerability Manager (GVM) API client."""

import httpx

from kahu.config import settings


class GreenborneClient:
    """Client for the Greenbone Security Assistant (GSA) REST API."""

    def __init__(self) -> None:
        self.base_url = settings.greenbone_url
        self.user = settings.greenbone_user
        self.password = settings.greenbone_password
        self._token: str | None = None

    # ── Auth ──────────────────────────────────────────────────

    async def authenticate(self) -> None:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/api/login",
                json={"username": self.user, "password": self.password},
            )
            resp.raise_for_status()
            self._token = resp.json().get("token")

    async def _ensure_auth(self) -> None:
        if not self._token:
            await self.authenticate()

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"}

    # ── Health ────────────────────────────────────────────────

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:  # noqa: S501
                resp = await client.get(f"{self.base_url}/api/version")
                return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    # ── Targets ───────────────────────────────────────────────

    async def get_targets(self) -> list[dict]:
        """List all scan targets."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/targets",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json().get("targets", [])

    async def create_target(self, name: str, hosts: str, port_list_id: str = "") -> dict:
        """Create a scan target (hosts = comma-separated IPs/CIDRs)."""
        await self._ensure_auth()
        body: dict = {"name": name, "hosts": hosts}
        if port_list_id:
            body["port_list_id"] = port_list_id
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/api/targets",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            return resp.json()

    # ── Scans / Tasks ─────────────────────────────────────────

    async def get_tasks(self) -> list[dict]:
        """List all scan tasks."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/tasks",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json().get("tasks", [])

    async def create_task(
        self, name: str, target_id: str, scan_config_id: str = ""
    ) -> dict:
        """Create a scan task."""
        await self._ensure_auth()
        body: dict = {"name": name, "target_id": target_id}
        if scan_config_id:
            body["scan_config_id"] = scan_config_id
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/api/tasks",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            return resp.json()

    async def start_task(self, task_id: str) -> dict:
        """Start a scan task."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/api/tasks/{task_id}/start",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_task(self, task_id: str) -> dict:
        """Get task details including status and progress."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/tasks/{task_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ── Results ───────────────────────────────────────────────

    async def get_results(self, task_id: str = "", severity_min: float = 0.0) -> list[dict]:
        """Get vulnerability results, optionally filtered by task and severity."""
        await self._ensure_auth()
        params: dict = {}
        if task_id:
            params["task_id"] = task_id
        if severity_min > 0:
            params["severity_min"] = str(severity_min)
        async with httpx.AsyncClient(verify=False, timeout=30) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/results",
                headers=self._headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json().get("results", [])

    async def get_reports(self, task_id: str = "") -> list[dict]:
        """List scan reports."""
        await self._ensure_auth()
        params: dict = {}
        if task_id:
            params["task_id"] = task_id
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/reports",
                headers=self._headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json().get("reports", [])
