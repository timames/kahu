"""Microsoft Azure / Graph client for connector ingestion.

Unlike ``clients/wazuh.py`` (one appliance-wide endpoint from settings), this
client is constructed **per connector instance** — each instance carries its
own tenant/client/secret, which is what makes multi-tenant ingestion work:
one ConnectorInstance per tenant, each with an isolated token cache.

Cloud support: Commercial and GCC High. The two clouds differ in *all three*
endpoints (login, Graph, Log Analytics) and — critically — in the OAuth scope:
a token for ``https://graph.microsoft.com/.default`` is worthless against
``graph.microsoft.us``. Tokens are therefore cached per resource scope, and
Graph and Log Analytics each acquire their own (they are different resources).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

# Endpoint map per cloud environment. DoD (`.dod.` endpoints) is deliberately
# out of scope — GCC High covers the compliance boundary Kahu targets.
CLOUDS: dict[str, dict[str, str]] = {
    "commercial": {
        "login": "https://login.microsoftonline.com",
        "graph": "https://graph.microsoft.com",
        "log_analytics": "https://api.loganalytics.io",
    },
    "gcc_high": {
        "login": "https://login.microsoftonline.us",
        "graph": "https://graph.microsoft.us",
        "log_analytics": "https://api.loganalytics.us",
    },
}

# Refresh a cached token this many seconds before its stated expiry.
_TOKEN_EARLY_REFRESH = 300

_TIMEOUT = 30.0


class AzureAuthError(Exception):
    """Credential/consent-class failure (bad secret, unknown app/tenant).

    Distinct from transient HTTP errors so the poller can mark the instance
    ERROR (needs operator attention) instead of retrying forever.
    """


class AzureClient:
    """App-only (client credentials) client for Graph + Log Analytics."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        cloud: str = "commercial",
    ) -> None:
        if cloud not in CLOUDS:
            raise ValueError(f"Unknown cloud environment: {cloud}")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.cloud = cloud
        self.endpoints = CLOUDS[cloud]
        # scope -> (access_token, expires_at_epoch)
        self._tokens: dict[str, tuple[str, float]] = {}

    # ── OAuth ─────────────────────────────────────────────

    async def _get_token(self, resource: str) -> str:
        """Client-credentials token for one resource, cached per scope."""
        scope = f"{resource}/.default"
        cached = self._tokens.get(scope)
        if cached and cached[1] - _TOKEN_EARLY_REFRESH > time.monotonic():
            return cached[0]

        url = f"{self.endpoints['login']}/{self.tenant_id}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": scope,
                },
            )
        if resp.status_code >= 400:
            # Token-endpoint 4xx is always a credential/config problem, never
            # transient. Surface Microsoft's error description (contains the
            # AADSTS code operators search for) but never the secret.
            try:
                body = resp.json()
                detail = body.get("error_description") or body.get("error") or resp.text
            except ValueError:
                detail = resp.text
            raise AzureAuthError(f"Token request failed ({resp.status_code}): {detail[:300]}")
        token = str(resp.json()["access_token"])
        expires_in = float(resp.json().get("expires_in", 3600))
        self._tokens[scope] = (token, time.monotonic() + expires_in)
        return token

    # ── Microsoft Graph ───────────────────────────────────

    async def graph_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int = 200,
    ) -> list[dict[str, Any]]:
        """GET a Graph collection, following @odata.nextLink up to max_items.

        The item cap bounds a single poll cycle; the poller's watermark picks
        up the remainder on the next cycle.
        """
        token = await self._get_token(self.endpoints["graph"])
        headers = {"Authorization": f"Bearer {token}"}
        url: str | None = f"{self.endpoints['graph']}{path}"
        items: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            while url and len(items) < max_items:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                body = resp.json()
                items.extend(body.get("value", []))
                url = body.get("@odata.nextLink")
                params = None  # nextLink already encodes the query
        return items[:max_items]

    # ── Azure Log Analytics ───────────────────────────────

    async def la_query(
        self, workspace_id: str, kql: str, timespan: str | None = None
    ) -> dict[str, Any]:
        """Run a KQL query against a Log Analytics workspace.

        Returns the raw response body (``tables`` -> columns/rows).
        ``timespan`` is an ISO-8601 interval (e.g. ``2026-01-01T00:00:00Z/2026-01-01T01:00:00Z``).
        """
        token = await self._get_token(self.endpoints["log_analytics"])
        url = f"{self.endpoints['log_analytics']}/v1/workspaces/{workspace_id}/query"
        payload: dict[str, Any] = {"query": kql}
        if timespan:
            payload["timespan"] = timespan
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            resp.raise_for_status()
            return dict(resp.json())


def la_rows_as_dicts(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Zip a Log Analytics query response's first table into row dicts."""
    tables = response.get("tables") or []
    if not tables:
        return []
    table = tables[0]
    columns = [c.get("name", f"col{i}") for i, c in enumerate(table.get("columns", []))]
    return [dict(zip(columns, row, strict=False)) for row in table.get("rows", [])]
