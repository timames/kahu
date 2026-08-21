"""Real connection tests for the Azure connector types.

Test = token acquisition + one cheap probe against the actual API the poller
will use, with error mapping to actionable operator guidance (invalid secret
vs missing application permission / admin consent). Other catalog types keep
the `_simulate_test` placeholder in api/connectors.py.
"""

from __future__ import annotations

import logging

import httpx

from kahu.clients.azure import AzureAuthError, AzureClient
from kahu.models.connectors import ConnectorInstance
from kahu.services.connectors.azure_poller import _build_client

logger = logging.getLogger(__name__)

AZURE_TEST_TYPES = frozenset({"microsoft_defender", "azure_log_analytics", "entra_signin"})

# AADSTS codes worth translating — the raw error_description is included too.
_AUTH_HINTS = (
    ("AADSTS7000215", "The client secret is invalid (check for an expired or mistyped secret)."),
    ("AADSTS700016", "The Application (Client) ID was not found in this tenant."),
    ("AADSTS90002", "The Tenant ID was not found — check the ID and cloud environment."),
    ("AADSTS500011", "The API resource is not available in this tenant/cloud environment."),
)

_PERMISSION_HELP = {
    "microsoft_defender": "SecurityAlert.Read.All (application) on Microsoft Graph",
    "entra_signin": "AuditLog.Read.All + Directory.Read.All (application) on Microsoft Graph",
    "azure_log_analytics": (
        "Data.Read (application) on the Log Analytics API plus the"
        " Log Analytics Reader RBAC role on the workspace"
    ),
}


async def run_azure_test(
    instance: ConnectorInstance, client: AzureClient | None = None
) -> tuple[bool, str]:
    """Probe the API for one Azure connector instance. Returns (success, message)."""
    client = client or _build_client(instance)
    cfg = {**(instance.config or {}), **(instance.credentials or {})}
    try:
        if instance.connector_type == "microsoft_defender":
            await client.graph_get("/v1.0/security/alerts_v2", params={"$top": 1}, max_items=1)
            return True, "Connected — Defender alerts are readable."
        if instance.connector_type == "entra_signin":
            await client.graph_get("/v1.0/auditLogs/signIns", params={"$top": 1}, max_items=1)
            return True, "Connected — Entra sign-in logs are readable."
        # azure_log_analytics
        workspace_id = str(cfg.get("workspace_id", ""))
        await client.la_query(workspace_id, "print probe=1", timespan="PT5M")
        return True, "Connected — Log Analytics workspace query succeeded."
    except AzureAuthError as exc:
        msg = str(exc)
        for code, hint in _AUTH_HINTS:
            if code in msg:
                return False, f"Authentication failed: {hint}"
        return False, f"Authentication failed: {msg[:300]}"
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status in (401, 403):
            needed = _PERMISSION_HELP.get(instance.connector_type, "the required API permission")
            return False, (
                f"Authenticated, but the API returned {status} — grant {needed}"
                " and ensure admin consent is granted."
            )
        if status == 404:
            return False, (
                "API endpoint or workspace not found — check the workspace ID"
                " and cloud environment."
            )
        return False, f"API request failed with HTTP {status}."
    except httpx.HTTPError as exc:
        return False, f"Could not reach the Microsoft API: {exc}"
    except Exception as exc:
        logger.warning("Azure connector test failed unexpectedly", exc_info=True)
        return False, f"Test failed: {type(exc).__name__}: {exc}"
