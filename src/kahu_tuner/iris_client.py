"""DFIR-IRIS API client for proposal task management."""

from __future__ import annotations

import httpx


class IRISClient:
    """Client for the DFIR-IRIS case management API."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def create_task(
        self,
        title: str,
        description: str,
        assignee_group: str = "ComplyHI",
        case_id: int | None = None,
    ) -> dict:
        """Create a task in IRIS for proposal review.

        For L0/L1 deployments, proposals are gated on human approval
        recorded in IRIS.
        """
        body: dict = {
            "task_title": title,
            "task_description": description,
            "task_assignee_group": assignee_group,
            "task_status_id": 1,  # Open
        }
        if case_id:
            body["task_case_id"] = case_id

        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/api/v2/tasks/add",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            return resp.json()

    async def get_task(self, task_id: int) -> dict:
        """Get task details including approval status."""
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/api/v2/tasks/{task_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def is_task_approved(self, task_id: int) -> bool:
        """Check if a task has been approved (status = completed/approved)."""
        task = await self.get_task(task_id)
        data = task.get("data", task)
        status_id = data.get("task_status_id", 0)
        # Status 2 = completed/approved in IRIS
        return status_id == 2

    async def update_task_status(self, task_id: int, status_id: int, note: str = "") -> dict:
        """Update task status (e.g., mark as applied)."""
        body: dict = {"task_status_id": status_id}
        if note:
            body["task_description"] = note

        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.put(
                f"{self.base_url}/api/v2/tasks/{task_id}",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            return resp.json()

    async def health(self) -> bool:
        """Check IRIS API reachability."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:  # noqa: S501
                resp = await client.get(
                    f"{self.base_url}/api/versions",
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False
