"""Transform Microsoft security events into Wazuh-shaped pipeline alerts.

Synthetic rule-ID reservation
-----------------------------
The block **200000-209999** is reserved for Kahu-native (non-Wazuh) connector
sources. Wazuh's own rules and our custom local rules (100xxx) never use it.
Current assignments:

    200101-200104   Microsoft Defender alert: informational/low/medium/high
                    -> levels 3 / 5 / 10 / 13
    200200          Entra ID sign-in (successful, no risk — "all" filter only)
                    -> level 3
    200201          Entra ID failed sign-in (no risk signal) -> level 5
    200202-200204   Entra ID risky sign-in: low/medium/high -> levels 7 / 10 / 13
    200301          Azure Log Analytics query row -> config default_level or
                    per-row ``KahuLevel``, clamped to 3-15

Governing invariant: Defender *high* (200104) and Entra *high risk* (200204)
map to level 13 — at or above the level-12 critical band — so the deterministic
pipeline rates them critical regardless of anything the model says. Both IDs
are additionally in ``CRITICAL_RULE_IDS`` (filters.py): unmutable, never
suppressed, never auto-dismissed. Defense in depth: even if a level mapping
here regressed, the rule-ID check would still hold the floor.

The pipeline maps ``rule.level`` deterministically: <3 suppressed, 3-6 low,
7-9 medium, 10-11 high, >=12 critical.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# ── Rule tables ────────────────────────────────────────────

DEFENDER_SEVERITY_RULES: dict[str, tuple[str, int]] = {
    "informational": ("200101", 3),
    "low": ("200102", 5),
    "medium": ("200103", 10),
    "high": ("200104", 13),  # critical band — CRITICAL_RULE_IDS member
}

ENTRA_SIGNIN_OK_RULE: tuple[str, int] = ("200200", 3)
ENTRA_FAILED_RULE: tuple[str, int] = ("200201", 5)
ENTRA_RISK_RULES: dict[str, tuple[str, int]] = {
    "low": ("200202", 7),
    "medium": ("200203", 10),
    "high": ("200204", 13),  # critical band — CRITICAL_RULE_IDS member
}

LA_RULE_ID = "200301"
LA_LEVEL_MIN = 3
LA_LEVEL_MAX = 15

_FULL_LOG_MAX = 4000

_RISK_LEVELS = {"low", "medium", "high"}


def _clamp(level: int, lo: int = LA_LEVEL_MIN, hi: int = LA_LEVEL_MAX) -> int:
    return max(lo, min(hi, level))


def _full_log(obj: dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)[:_FULL_LOG_MAX]


# ── Microsoft Defender XDR (Graph security/alerts_v2) ──────


def transform_defender_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Map a Graph security alert (alerts_v2) to a Wazuh-shaped dict."""
    severity = str(alert.get("severity") or "informational").lower()
    rule_id, level = DEFENDER_SEVERITY_RULES.get(severity, DEFENDER_SEVERITY_RULES["informational"])

    device = None
    for ev in alert.get("evidence") or []:
        if str(ev.get("@odata.type", "")).endswith("deviceEvidence"):
            device = ev.get("deviceDnsName") or ev.get("hostName")
            if device:
                break

    title = alert.get("title") or "Defender alert"
    return {
        "id": f"defender:{alert.get('id')}",
        "timestamp": alert.get("createdDateTime"),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": f"Microsoft Defender: {title}",
            "groups": ["azure", "microsoft_defender", str(alert.get("category") or "").lower()],
        },
        "agent": {"id": "000", "name": device or "microsoft-defender"},
        "location": "microsoft_defender",
        "data": {
            "defender_alert_id": alert.get("id"),
            "incident_id": alert.get("incidentId"),
            "web_url": alert.get("alertWebUrl"),
            "category": alert.get("category"),
            "severity": severity,
            "detection_source": alert.get("detectionSource"),
        },
        "full_log": _full_log(alert),
    }


# ── Entra ID sign-in logs (Graph auditLogs/signIns) ────────


def _signin_risk(signin: dict[str, Any]) -> str | None:
    """Highest applicable risk level, or None when not risky."""
    for key in ("riskLevelDuringSignIn", "riskLevelAggregated"):
        val = str(signin.get(key) or "").lower()
        if val in _RISK_LEVELS:
            return val
    return None


def _signin_failed(signin: dict[str, Any]) -> bool:
    status = signin.get("status") or {}
    code = status.get("errorCode")
    return code is not None and code != 0


def signin_matches_filter(signin: dict[str, Any], mode: str) -> bool:
    """Client-side sign-in filter — OData filters on errorCode/risk are
    unreliable app-only, so only time filtering happens server-side."""
    risky = _signin_risk(signin) is not None
    failed = _signin_failed(signin)
    if mode == "risky_only":
        return risky
    if mode == "failed_only":
        return failed
    if mode == "all":
        return True
    # default: risky_or_failed
    return risky or failed


def transform_entra_signin(signin: dict[str, Any]) -> dict[str, Any]:
    """Map an Entra sign-in log entry to a Wazuh-shaped dict.

    Identity-centric: ``agent.name`` is the UPN, so per-"agent" disposition
    history and dedup group by user, not by appliance. Failed sign-ins carry
    the ``authentication_failed`` group so the existing auth-correlation
    filter (brute-force burst detection) picks them up.
    """
    risk = _signin_risk(signin)
    failed = _signin_failed(signin)
    if risk is not None:
        rule_id, level = ENTRA_RISK_RULES[risk]
        desc = f"Entra ID risky sign-in ({risk} risk)"
    elif failed:
        rule_id, level = ENTRA_FAILED_RULE
        desc = "Entra ID failed sign-in"
    else:
        rule_id, level = ENTRA_SIGNIN_OK_RULE
        desc = "Entra ID sign-in"

    groups = ["azure", "entra_id", "authentication"]
    if failed:
        groups.append("authentication_failed")

    upn = signin.get("userPrincipalName") or "unknown-user"
    location = signin.get("location") or {}
    status = signin.get("status") or {}
    return {
        "id": f"entra:{signin.get('id')}",
        "timestamp": signin.get("createdDateTime"),
        "rule": {"id": rule_id, "level": level, "description": desc, "groups": groups},
        "agent": {"id": "000", "name": upn},
        "location": "entra_signin",
        "data": {
            "srcip": signin.get("ipAddress"),
            "srcuser": upn,
            "app": signin.get("appDisplayName"),
            "client_app": signin.get("clientAppUsed"),
            "error_code": status.get("errorCode"),
            "failure_reason": status.get("failureReason"),
            "risk_level": risk,
            "risk_state": signin.get("riskState"),
            "city": location.get("city"),
            "country": location.get("countryOrRegion"),
        },
        "full_log": _full_log(signin),
    }


# ── Azure Log Analytics (KQL query rows) ───────────────────


def la_row_id(workspace_id: str, row: dict[str, Any]) -> str:
    """Stable dedup id for a query row — LA rows have no natural id."""
    digest = hashlib.sha256(
        (workspace_id + json.dumps(row, sort_keys=True, default=str)).encode()
    ).hexdigest()
    return f"la:{digest[:32]}"


def transform_la_row(
    row: dict[str, Any],
    workspace_id: str,
    query_name: str = "Log Analytics query",
    default_level: int = 7,
) -> dict[str, Any]:
    """Map one KQL result row to a Wazuh-shaped dict.

    A row may carry its own ``KahuLevel`` column (projected in the KQL) to
    override the connector-wide default; both are clamped to 3-15 so a query
    can neither silently suppress (<3) nor exceed the scale.
    """
    level = default_level
    raw_level = row.get("KahuLevel")
    if raw_level is not None:
        try:
            level = int(raw_level)
        except (TypeError, ValueError):
            level = default_level
    level = _clamp(level)

    agent = row.get("Computer") or row.get("Resource") or "log-analytics"
    return {
        "id": la_row_id(workspace_id, row),
        "timestamp": row.get("TimeGenerated"),
        "rule": {
            "id": LA_RULE_ID,
            "level": level,
            "description": f"Azure Log Analytics: {query_name}",
            "groups": ["azure", "log_analytics"],
        },
        "agent": {"id": "000", "name": str(agent)},
        "location": "azure_log_analytics",
        "data": {k: v for k, v in row.items() if v is not None},
        "full_log": _full_log(row),
    }
