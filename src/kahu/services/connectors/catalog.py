"""Built-in connector type catalog.

Each entry defines what a log source needs to connect:
auth method, required fields, setup guide URL, and test command.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectorField:
    name: str
    label: str
    field_type: str = "text"  # text, password, textarea, file, select
    required: bool = True
    placeholder: str = ""
    help_text: str = ""


@dataclass(frozen=True)
class ConnectorType:
    id: str
    name: str
    category: str  # endpoint, network, cloud, identity, email
    icon: str  # emoji for PWA display
    auth_method: str  # credentials, api_key, certificate, oauth, syslog
    fields: tuple[ConnectorField, ...] = ()
    setup_guide_url: str = ""
    description: str = ""
    events_per_day: str = ""  # typical volume hint


# ── Connector Catalog ──────────────────────────────────────

CATALOG: dict[str, ConnectorType] = {}


def _register(ct: ConnectorType) -> None:
    CATALOG[ct.id] = ct


# ── Endpoint Sources ───────────────────────────────────────

_register(
    ConnectorType(
        id="windows_event_log",
        name="Windows Event Logs",
        category="endpoint",
        icon="\U0001fa9f",  # 🪟
        auth_method="credentials",
        description="Active Directory, DNS, DHCP, and Windows security events via Wazuh agent.",
        events_per_day="1K–50K",
        setup_guide_url="https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html",
        fields=(
            ConnectorField(
                "server_address", "Server / Domain Controller IP", placeholder="192.168.1.10"
            ),
            ConnectorField(
                "username", "Domain Admin Username", placeholder="DOMAIN\\Administrator"
            ),
            ConnectorField("password", "Password", field_type="password"),
        ),
    )
)

_register(
    ConnectorType(
        id="linux_syslog",
        name="Linux Syslog",
        category="endpoint",
        icon="\U0001f427",  # 🐧
        auth_method="credentials",
        description=(
            "System logs, auth logs, and application logs"
            " from Linux hosts via Wazuh agent."
        ),
        events_per_day="500–20K",
        setup_guide_url="https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html",
        fields=(
            ConnectorField("host", "Host IP / Hostname", placeholder="10.0.0.50"),
            ConnectorField("username", "SSH Username", placeholder="root"),
            ConnectorField(
                "auth_type", "Auth Method", field_type="select", placeholder="password,ssh_key"
            ),
            ConnectorField("password", "Password or SSH Key", field_type="password"),
        ),
    )
)

_register(
    ConnectorType(
        id="macos_endpoint",
        name="macOS Endpoint",
        category="endpoint",
        icon="\U0001f34e",  # 🍎
        auth_method="credentials",
        description="macOS system logs, security events, and application logs via Wazuh agent.",
        events_per_day="500–10K",
        setup_guide_url="https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-macos.html",
        fields=(
            ConnectorField("host", "Host IP / Hostname", placeholder="10.0.0.60"),
            ConnectorField("username", "Admin Username", placeholder="admin"),
            ConnectorField("password", "Password", field_type="password"),
        ),
    )
)

# ── Network Sources ────────────────────────────────────────

_register(
    ConnectorType(
        id="palo_alto",
        name="Palo Alto Firewall",
        category="network",
        icon="\U0001f6e1\ufe0f",  # 🛡️
        auth_method="api_key",
        description="Threat, traffic, and URL filtering logs from Palo Alto Networks firewalls.",
        events_per_day="10K–500K",
        setup_guide_url="https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key",
        fields=(
            ConnectorField("host", "Firewall IP / Hostname", placeholder="192.168.1.1"),
            ConnectorField(
                "api_key",
                "API Key",
                field_type="password",
                help_text="Device > API Keys in the PAN-OS web UI",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="fortinet",
        name="FortiGate Firewall",
        category="network",
        icon="\U0001f6e1\ufe0f",  # 🛡️
        auth_method="api_key",
        description="IPS, traffic, and web filter logs from FortiGate firewalls.",
        events_per_day="10K–500K",
        setup_guide_url="https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023/rest-api-administrator",
        fields=(
            ConnectorField("host", "FortiGate IP / Hostname", placeholder="192.168.1.1"),
            ConnectorField(
                "api_key",
                "REST API Key",
                field_type="password",
                help_text="System > Administrators > REST API Admin",
            ),
            ConnectorField("vdom", "VDOM", required=False, placeholder="root"),
        ),
    )
)

_register(
    ConnectorType(
        id="pfsense",
        name="pfSense / OPNsense",
        category="network",
        icon="\U0001f5a7",  # 🖧
        auth_method="syslog",
        description="Firewall, IDS/IPS, and system logs via syslog forwarding.",
        events_per_day="5K–100K",
        setup_guide_url="https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html",
        fields=(
            ConnectorField("host", "pfSense IP", placeholder="192.168.1.1"),
            ConnectorField("syslog_port", "Syslog Port", placeholder="514"),
            ConnectorField("protocol", "Protocol", field_type="select", placeholder="udp,tcp"),
        ),
    )
)

_register(
    ConnectorType(
        id="meraki",
        name="Cisco Meraki",
        category="network",
        icon="\U0001f4f6",  # 📶
        auth_method="api_key",
        description="Network events, security events, and client activity from Meraki dashboard.",
        events_per_day="1K–50K",
        setup_guide_url="https://developer.cisco.com/meraki/api-v1/authorization/",
        fields=(
            ConnectorField(
                "api_key",
                "Dashboard API Key",
                field_type="password",
                help_text="Organization > Settings > Dashboard API access",
            ),
            ConnectorField("org_id", "Organization ID", placeholder="123456"),
        ),
    )
)

_register(
    ConnectorType(
        id="ubiquiti",
        name="Ubiquiti UniFi",
        category="network",
        icon="\U0001f4f6",  # 📶
        auth_method="credentials",
        description="Network events, IDS alerts, and client activity from UniFi controllers.",
        events_per_day="1K–20K",
        setup_guide_url="https://help.ui.com/hc/en-us/articles/226218448",
        fields=(
            ConnectorField(
                "controller_url", "Controller URL", placeholder="https://unifi.local:8443"
            ),
            ConnectorField("username", "Admin Username", placeholder="admin"),
            ConnectorField("password", "Password", field_type="password"),
        ),
    )
)

# ── Cloud Sources ──────────────────────────────────────────

_register(
    ConnectorType(
        id="microsoft_365",
        name="Microsoft 365",
        category="cloud",
        icon="\u2601\ufe0f",  # ☁️
        auth_method="credentials",
        description="Audit logs, sign-in events, and security alerts from M365 / Entra ID.",
        events_per_day="1K–100K",
        setup_guide_url="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
        fields=(
            ConnectorField(
                "tenant_id", "Tenant ID", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ),
            ConnectorField(
                "client_id",
                "Application (Client) ID",
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            ),
            ConnectorField(
                "client_secret",
                "Client Secret",
                field_type="password",
                help_text="Entra ID > App registrations > Certificates & secrets",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="google_workspace",
        name="Google Workspace",
        category="cloud",
        icon="\u2601\ufe0f",  # ☁️
        auth_method="certificate",
        description="Admin audit, login events, and Drive activity from Google Workspace.",
        events_per_day="500–50K",
        setup_guide_url="https://support.google.com/a/answer/7281227",
        fields=(
            ConnectorField(
                "customer_id",
                "Customer ID",
                placeholder="C0xxxxxxx",
                help_text="Admin console > Account > Account settings",
            ),
            ConnectorField(
                "service_account_json",
                "Service Account Key (JSON)",
                field_type="textarea",
                help_text="GCP Console > IAM > Service Accounts > Keys > Add Key > JSON",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="aws_cloudtrail",
        name="AWS CloudTrail",
        category="cloud",
        icon="\u2601\ufe0f",  # ☁️
        auth_method="api_key",
        description="API activity, console logins, and resource changes across AWS accounts.",
        events_per_day="5K–500K",
        setup_guide_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        fields=(
            ConnectorField("access_key_id", "Access Key ID", placeholder="AKIA..."),
            ConnectorField("secret_access_key", "Secret Access Key", field_type="password"),
            ConnectorField("region", "Region", placeholder="us-east-1"),
            ConnectorField(
                "trail_name", "Trail Name", required=False, placeholder="management-events"
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="azure_activity",
        name="Azure Activity Log",
        category="cloud",
        icon="\u2601\ufe0f",  # ☁️
        auth_method="credentials",
        description=(
            "Azure resource operations, policy events,"
            " and service health from Azure Monitor."
        ),
        events_per_day="1K–100K",
        setup_guide_url="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
        fields=(
            ConnectorField(
                "tenant_id", "Tenant ID", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ),
            ConnectorField(
                "client_id",
                "Application (Client) ID",
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            ),
            ConnectorField("client_secret", "Client Secret", field_type="password"),
            ConnectorField(
                "subscription_id",
                "Subscription ID",
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            ),
        ),
    )
)

# ── Microsoft Azure (native Kahu pollers) ─────────────────
#
# These three types are ingested by Kahu itself (services/connectors/
# azure_poller.py), not via Wazuh. They share an Entra app registration:
# one ConnectorInstance per tenant (multi-tenant = multiple instances).
# Setup walkthrough: docs/connectors/microsoft-azure.md.


def _azure_common_fields(secret_help: str) -> tuple[ConnectorField, ...]:
    return (
        ConnectorField(
            "tenant_id", "Tenant ID", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ),
        ConnectorField(
            "client_id",
            "Application (Client) ID",
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        ),
        ConnectorField(
            "client_secret",
            "Client Secret",
            field_type="password",
            help_text=secret_help,
        ),
        ConnectorField(
            "cloud_environment",
            "Cloud Environment",
            field_type="select",
            placeholder="commercial,gcc_high",
            help_text="GCC High tenants use login.microsoftonline.us / graph.microsoft.us",
        ),
    )


_register(
    ConnectorType(
        id="microsoft_defender",
        name="Microsoft Defender XDR",
        category="cloud",
        icon="\U0001f6e1\ufe0f",  # 🛡️
        auth_method="credentials",
        description=(
            "Security alerts from Defender for Endpoint, Office 365, Identity,"
            " and Cloud Apps via the Microsoft Graph security API."
        ),
        events_per_day="10–1K",
        setup_guide_url="https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2",
        fields=_azure_common_fields(
            "App registration needs the SecurityAlert.Read.All APPLICATION"
            " permission on Microsoft Graph, with admin consent granted."
        ),
    )
)

_register(
    ConnectorType(
        id="azure_log_analytics",
        name="Azure Log Analytics",
        category="cloud",
        icon="\u2601\ufe0f",  # ☁️
        auth_method="credentials",
        description=(
            "Rows from a scheduled KQL query against a Log Analytics workspace"
            " (Sentinel tables, custom logs, Azure diagnostics)."
        ),
        events_per_day="Depends on query — keep it narrow",
        setup_guide_url="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview",
        fields=(
            *_azure_common_fields(
                "App needs the Data.Read APPLICATION permission on the Log"
                " Analytics API (admin consent) AND the Log Analytics Reader"
                " RBAC role on the workspace."
            ),
            ConnectorField(
                "workspace_id",
                "Workspace ID",
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                help_text="Log Analytics workspace > Overview > Workspace ID (a GUID)",
            ),
            ConnectorField(
                "kql_query",
                "KQL Query",
                field_type="textarea",
                placeholder="SecurityEvent | where EventID == 4625",
                help_text=(
                    "Runs each poll over the new time window only. Do NOT point"
                    " this at high-volume tables — every row becomes a triage"
                    " alert. Optionally project a KahuLevel column (3-15) to set"
                    " per-row severity."
                ),
            ),
            ConnectorField(
                "query_name",
                "Query Name",
                placeholder="Failed Windows logons",
                help_text="Shown as the alert description in the feed",
            ),
            ConnectorField(
                "default_level",
                "Default Severity Level",
                field_type="select",
                placeholder="5,7,10,12",
                help_text="Used when a row has no KahuLevel: 5=low 7=medium 10=high 12=critical",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="entra_signin",
        name="Entra ID Sign-in Logs",
        category="identity",
        icon="\U0001f511",  # 🔑
        auth_method="credentials",
        description=(
            "Risky and failed sign-ins from Entra ID (Azure AD) via the Microsoft"
            " Graph auditLogs API. Requires Entra ID P1 or P2."
        ),
        events_per_day="100–50K (mode-dependent)",
        setup_guide_url="https://learn.microsoft.com/en-us/graph/api/signin-list",
        fields=(
            *_azure_common_fields(
                "App registration needs the AuditLog.Read.All and"
                " Directory.Read.All APPLICATION permissions on Microsoft"
                " Graph, with admin consent granted."
            ),
            ConnectorField(
                "signin_filter",
                "Sign-ins to Ingest",
                field_type="select",
                placeholder="risky_or_failed,risky_only,failed_only,all",
                help_text=(
                    "'all' ingests every sign-in — avoid on large tenants;"
                    " each event is triaged individually."
                ),
            ),
        ),
    )
)

# ── Identity Sources ───────────────────────────────────────

_register(
    ConnectorType(
        id="okta",
        name="Okta",
        category="identity",
        icon="\U0001f511",  # 🔑
        auth_method="api_key",
        description="Authentication events, user lifecycle, and policy violations from Okta.",
        events_per_day="1K–50K",
        setup_guide_url="https://developer.okta.com/docs/guides/create-an-api-token/main/",
        fields=(
            ConnectorField("domain", "Okta Domain", placeholder="yourorg.okta.com"),
            ConnectorField(
                "api_token",
                "API Token",
                field_type="password",
                help_text="Security > API > Tokens > Create Token",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="duo",
        name="Duo Security",
        category="identity",
        icon="\U0001f511",  # 🔑
        auth_method="api_key",
        description="MFA authentication logs, admin actions, and telephony events from Duo.",
        events_per_day="500–10K",
        setup_guide_url="https://duo.com/docs/adminapi",
        fields=(
            ConnectorField(
                "api_hostname", "API Hostname", placeholder="api-XXXXXXXX.duosecurity.com"
            ),
            ConnectorField("integration_key", "Integration Key"),
            ConnectorField("secret_key", "Secret Key", field_type="password"),
        ),
    )
)

# ── EDR Sources ────────────────────────────────────────────

_register(
    ConnectorType(
        id="sentinelone",
        name="SentinelOne",
        category="endpoint",
        icon="\U0001f6e1\ufe0f",  # 🛡️
        auth_method="api_key",
        description=(
            "Threat detections, agent activity,"
            " and deep visibility events from SentinelOne."
        ),
        events_per_day="5K–100K",
        setup_guide_url="https://usea1-partners.sentinelone.net/docs/en/generating-api-tokens.html",
        fields=(
            ConnectorField(
                "console_url", "Console URL", placeholder="https://usea1.sentinelone.net"
            ),
            ConnectorField(
                "api_token",
                "API Token",
                field_type="password",
                help_text="Settings > Users > API Token",
            ),
        ),
    )
)

_register(
    ConnectorType(
        id="crowdstrike",
        name="CrowdStrike Falcon",
        category="endpoint",
        icon="\U0001f6e1\ufe0f",  # 🛡️
        auth_method="credentials",
        description="Detection events, incident data, and host activity from CrowdStrike Falcon.",
        events_per_day="5K–200K",
        setup_guide_url="https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis",
        fields=(
            ConnectorField("client_id", "API Client ID"),
            ConnectorField(
                "client_secret",
                "API Client Secret",
                field_type="password",
                help_text="Support and resources > API Clients and Keys",
            ),
            ConnectorField(
                "base_url",
                "CrowdStrike Cloud",
                field_type="select",
                placeholder="https://api.crowdstrike.com,https://api.us-2.crowdstrike.com,https://api.eu-1.crowdstrike.com",
            ),
        ),
    )
)

# ── Vulnerability Scanners ────────────────────────────────

_register(
    ConnectorType(
        id="greenbone",
        name="Greenbone OpenVAS",
        category="vulnerability",
        icon="\U0001f50d",  # magnifying glass
        auth_method="credentials",
        description=(
            "Network vulnerability scanning and assessment"
            " via Greenbone Community Edition (OpenVAS)."
        ),
        events_per_day="Varies by scan scope",
        setup_guide_url="https://greenbone.github.io/docs/latest/",
        fields=(
            ConnectorField(
                "host",
                "Scanner Host",
                placeholder="greenbone",
                help_text="Hostname or IP of the Greenbone appliance",
            ),
            ConnectorField("port", "API Port", placeholder="9390", required=False),
            ConnectorField("username", "Admin Username", placeholder="admin"),
            ConnectorField("password", "Admin Password", field_type="password"),
        ),
    )
)

# ── Generic / Catch-All ───────────────────────────────────

_register(
    ConnectorType(
        id="generic_syslog",
        name="Generic Syslog",
        category="network",
        icon="\U0001f4cb",  # 📋
        auth_method="syslog",
        description="Any device that can forward syslog (RFC 3164 or RFC 5424). Point it at Kahu.",
        events_per_day="Varies",
        setup_guide_url="https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-to-collect-syslog.html",
        fields=(
            ConnectorField(
                "source_name",
                "Source Name",
                placeholder="lobby-switch-01",
                help_text="A friendly name for this source",
            ),
            ConnectorField(
                "source_host",
                "Sender IP / Hostname",
                required=False,
                placeholder="192.168.1.1",
                help_text=(
                    "IP or syslog hostname the device sends as — used to count its events"
                ),
            ),
            ConnectorField("syslog_port", "Syslog Port", placeholder="514"),
            ConnectorField(
                "protocol", "Protocol", field_type="select", placeholder="udp,tcp,tcp+tls"
            ),
        ),
    )
)


def get_catalog() -> list[dict]:
    """Return catalog as serializable list, grouped by category."""
    return [
        {
            "id": ct.id,
            "name": ct.name,
            "category": ct.category,
            "icon": ct.icon,
            "auth_method": ct.auth_method,
            "description": ct.description,
            "events_per_day": ct.events_per_day,
            "setup_guide_url": ct.setup_guide_url,
            "fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "type": f.field_type,
                    "required": f.required,
                    "placeholder": f.placeholder,
                    "help_text": f.help_text,
                }
                for f in ct.fields
            ],
        }
        for ct in CATALOG.values()
    ]


def get_categories() -> list[dict]:
    """Return categories with counts."""
    cats: dict[str, int] = {}
    for ct in CATALOG.values():
        cats[ct.category] = cats.get(ct.category, 0) + 1
    labels = {
        "endpoint": "Endpoints & EDR",
        "network": "Network & Firewall",
        "cloud": "Cloud Platforms",
        "identity": "Identity & MFA",
        "vulnerability": "Vulnerability Scanners",
    }
    return [{"id": k, "name": labels.get(k, k.title()), "count": v} for k, v in cats.items()]
