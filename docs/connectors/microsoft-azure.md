# Microsoft Azure / Defender Connectors

Kahu ingests three Microsoft sources natively — no Wazuh agent or syslog hop
involved. A background poller inside Kahu pulls each source every 60 seconds
and feeds events through the full triage pipeline.

| Connector | Source API | What you get |
|---|---|---|
| Microsoft Defender XDR | Graph `security/alerts_v2` | Alerts from Defender for Endpoint, Office 365, Identity, Cloud Apps |
| Entra ID Sign-in Logs | Graph `auditLogs/signIns` | Risky and failed sign-ins (Entra ID P1/P2 required) |
| Azure Log Analytics | Log Analytics query API | Rows from a KQL query you define (Sentinel tables, custom logs) |

All three authenticate as an **Entra app registration** with client-credential
(application) permissions. One app registration can serve all three connectors
in a tenant.

## 1. Register the app

1. Entra admin center → **App registrations** → **New registration**.
2. Name it (e.g. `kahu-ingest`), single tenant, no redirect URI. Register.
3. Note the **Application (client) ID** and **Directory (tenant) ID** from the
   Overview page.
4. **Certificates & secrets** → **New client secret**. Copy the secret *value*
   immediately (it is only shown once). Note the expiry — Kahu will show the
   connector as ERROR when the secret expires.

## 2. Grant API permissions (per source)

**App registrations → API permissions → Add a permission**, choose
**Application permissions** (not Delegated), then click
**Grant admin consent** — nothing works without consent.

| Connector | API | Application permission |
|---|---|---|
| Microsoft Defender XDR | Microsoft Graph | `SecurityAlert.Read.All` |
| Entra ID Sign-in Logs | Microsoft Graph | `AuditLog.Read.All` and `Directory.Read.All` |
| Azure Log Analytics | Log Analytics API (`Data.Read`) | `Data.Read` |

Log Analytics additionally needs an **RBAC role**: on the target workspace,
**Access control (IAM) → Add role assignment → Log Analytics Reader**, assigned
to the app registration's service principal.

> The "Log Analytics API" appears in the Add-a-permission dialog under
> **APIs my organization uses** — search for "Log Analytics".

## 3. Add the connector in Kahu

Connectors & Endpoints → catalog → pick the type, then enter Tenant ID,
Client ID, Client Secret, and the cloud environment. Use **Test** — it performs
a real token acquisition plus a probe API call and reports *actionable* errors:
an invalid secret is reported differently from a missing permission or missing
admin consent. The connector must be ACTIVE (test passed) before the poller
picks it up.

First poll starts 15 minutes back — Kahu does not drain tenant history.

### Commercial vs GCC High

Select the matching **Cloud Environment**. The two clouds differ in every
endpoint *and* in the OAuth token audience, so a wrong selection fails
authentication even with perfect credentials.

| | Commercial | GCC High |
|---|---|---|
| Login | `login.microsoftonline.com` | `login.microsoftonline.us` |
| Graph | `graph.microsoft.com` | `graph.microsoft.us` |
| Log Analytics | `api.loganalytics.io` | `api.loganalytics.us` |

DoD endpoints (`*.dod.*`) are out of scope.

### Multi-tenant

One connector instance = one tenant. To monitor several tenants (e.g. MSP use),
register an app in each tenant and add one connector instance per tenant, each
with its own tenant/client/secret. Instances poll and fail independently — a
revoked secret in one tenant marks only that instance ERROR.

## Severity mapping

Events enter the pipeline with synthetic rule IDs in the reserved
200000–209999 block:

| Rule ID | Event | Level → severity |
|---|---|---|
| 200101–200103 | Defender informational / low / medium | 3 / 5 / 10 |
| 200104 | **Defender high** | 13 → critical |
| 200200 | Entra successful sign-in ("all" mode only) | 3 |
| 200201 | Entra failed sign-in | 5 |
| 200202–200203 | Entra risk low / medium | 7 / 10 |
| 200204 | **Entra high-risk sign-in** | 13 → critical |
| 200301 | Log Analytics row | config default, or per-row `KahuLevel` (clamped 3–15) |

`200104` and `200204` are in `CRITICAL_RULE_IDS`: they cannot be muted,
suppressed, or auto-dismissed, regardless of what the model recommends. The
ruleset governs.

For Log Analytics, project a `KahuLevel` column in your KQL to set severity
per row, e.g.:

```kusto
SecurityEvent
| where EventID == 4625
| extend KahuLevel = iff(TargetUserName == "Administrator", 12, 7)
```

## Volume warning

Every ingested event is triaged individually and the pipeline is serialized
through the local LLM (per-instance cap: 200 events per 60-second cycle;
the rest drains on later cycles).

- **Do not** point `kql_query` at high-volume tables (raw `SecurityEvent`,
  `Syslog`, flow logs). Filter aggressively in KQL.
- **Avoid** the `all` sign-in mode on tenants of any size; the default
  `risky_or_failed` is the intended operating mode.

## Operations notes

- The poll cursor (watermark + recent event ids) is stored per instance in the
  database — restarts neither re-ingest nor skip events.
- Auth-class failures (bad secret, missing consent, 401/403) mark the instance
  **ERROR** with the mapped message; transient API failures only set the error
  message and retry on the next cycle.
- Entra sign-ins are polled with a 5-minute lag window to absorb Microsoft's
  ingestion latency; expect sign-ins to appear in Kahu ~5–7 minutes after they
  occur.
