"""Wazuh API and indexer client."""

import httpx

from kuahene.config import settings


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

    async def get_alerts(self, limit: int = 20, offset: int = 0) -> dict:
        if not self._token:
            await self.authenticate()
        async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
            resp = await client.get(
                f"{self.base_url}/alerts",
                headers={"Authorization": f"Bearer {self._token}"},
                params={"limit": limit, "offset": offset},
            )
            resp.raise_for_status()
            return resp.json()


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
