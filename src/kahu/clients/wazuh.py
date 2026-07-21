"""Wazuh API and indexer client."""

import httpx

from kahu.config import settings


class WazuhAPIClient:
    """Client for the Wazuh management API (port 55000)."""

    def __init__(self) -> None:
        self.base_url = settings.wazuh_api_url
        self.user = settings.wazuh_api_user
        self.password = settings.wazuh_api_password
        self._token: str | None = None

    async def authenticate(self) -> None:
        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]

    async def _ensure_auth(self) -> None:
        if not self._token:
            await self.authenticate()

    async def api_get(self, path: str, params: dict | None = None) -> dict:
        """Generic authenticated GET against the Wazuh API."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def api_put(self, path: str, json: dict | None = None) -> dict:
        """Generic authenticated PUT."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.put(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                json=json,
            )
            resp.raise_for_status()
            return resp.json()

    async def api_delete(self, path: str, params: dict | None = None) -> dict:
        """Generic authenticated DELETE."""
        await self._ensure_auth()
        async with httpx.AsyncClient(verify=False, timeout=15) as client:  # noqa: S501
            resp = await client.delete(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def get_alerts(self, limit: int = 20, offset: int = 0) -> dict:
        return await self.api_get("/alerts", params={"limit": limit, "offset": offset})


class WazuhIndexerClient:
    """Client for the Wazuh indexer (OpenSearch, port 9200)."""

    def __init__(self) -> None:
        self.base_url = settings.wazuh_indexer_url
        self.auth = (settings.wazuh_indexer_user, settings.wazuh_indexer_password)

    async def search(self, index: str, query: dict) -> dict:
        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
            resp = await client.post(
                f"{self.base_url}/{index}/_search",
                json=query,
                auth=self.auth,
            )
            resp.raise_for_status()
            return resp.json()
