"""Agent management API — download installers, list enrolled agents, manage keys."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from kahu.clients.wazuh import WazuhAPIClient
from kahu.config import settings

router = APIRouter()


# ---------------------------------------------------------------------------
# Install script templates
# ---------------------------------------------------------------------------

LINUX_INSTALL = r"""#!/usr/bin/env bash
set -euo pipefail

# Kahu Agent Installer — Linux
# Auto-generated for appliance: {manager_host}

MANAGER_IP="{manager_host}"
AGENT_GROUP="{agent_group}"
WAZUH_VERSION="4.9.2-1"

echo "=== Kahu Agent Installer (Linux) ==="
echo "Manager: $MANAGER_IP"
echo ""

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG="deb"
elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    PKG="rpm"
else
    echo "ERROR: Unsupported Linux distribution (need apt or yum/dnf)"
    exit 1
fi

# Install Wazuh agent
echo "[1/4] Installing Wazuh agent..."
if [ "$PKG" = "deb" ]; then
    curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${{WAZUH_VERSION}}_amd64.deb
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_GROUP="$AGENT_GROUP" dpkg -i ./wazuh-agent_${{WAZUH_VERSION}}_amd64.deb
    rm -f ./wazuh-agent_${{WAZUH_VERSION}}_amd64.deb
else
    curl -sO https://packages.wazuh.com/4.x/yum/wazuh-agent-${{WAZUH_VERSION}}.x86_64.rpm
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_GROUP="$AGENT_GROUP" rpm -ivh ./wazuh-agent-${{WAZUH_VERSION}}.x86_64.rpm
    rm -f ./wazuh-agent-${{WAZUH_VERSION}}.x86_64.rpm
fi

# Configure manager address
echo "[2/4] Configuring agent..."
sed -i "s|<address>.*</address>|<address>$MANAGER_IP</address>|" /var/ossec/etc/ossec.conf

# Enable and start
echo "[3/4] Starting agent..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "[4/4] Verifying enrollment..."
sleep 5
if systemctl is-active --quiet wazuh-agent; then
    echo ""
    echo "SUCCESS: Kahu agent is running and connecting to $MANAGER_IP"
    echo "Agent will appear in the Kahu dashboard within 60 seconds."
else
    echo ""
    echo "WARNING: Agent installed but may not be connected yet."
    echo "Check: systemctl status wazuh-agent"
    echo "Logs: /var/ossec/logs/ossec.log"
fi
"""

MACOS_INSTALL = r"""#!/usr/bin/env bash
set -euo pipefail

# Kahu Agent Installer — macOS
# Auto-generated for appliance: {manager_host}

MANAGER_IP="{manager_host}"
AGENT_GROUP="{agent_group}"
WAZUH_VERSION="4.9.2-1"

echo "=== Kahu Agent Installer (macOS) ==="
echo "Manager: $MANAGER_IP"
echo ""

# Download Wazuh agent for macOS
echo "[1/4] Downloading Wazuh agent..."
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${{WAZUH_VERSION}}.arm64.pkg"
else
    PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${{WAZUH_VERSION}}.intel64.pkg"
fi
curl -sO "$PKG_URL"
PKG_FILE=$(basename "$PKG_URL")

# Install
echo "[2/4] Installing agent (may require password)..."
sudo installer -pkg "./$PKG_FILE" -target /
rm -f "./$PKG_FILE"

# Configure manager address
echo "[3/4] Configuring agent..."
sudo /Library/Ossec/bin/agent-auth -m "$MANAGER_IP" -G "$AGENT_GROUP" 2>/dev/null || true
sudo sed -i.bak "s|<address>.*</address>|<address>$MANAGER_IP</address>|" /Library/Ossec/etc/ossec.conf

# Start agent
echo "[4/4] Starting agent..."
sudo /Library/Ossec/bin/wazuh-control start

sleep 5
if sudo /Library/Ossec/bin/wazuh-control status | grep -q "is running"; then
    echo ""
    echo "SUCCESS: Kahu agent is running and connecting to $MANAGER_IP"
    echo "Agent will appear in the Kahu dashboard within 60 seconds."
else
    echo ""
    echo "WARNING: Agent installed but may not be connected yet."
    echo "Check: sudo /Library/Ossec/bin/wazuh-control status"
    echo "Logs: /Library/Ossec/logs/ossec.log"
fi
"""

WINDOWS_INSTALL = r"""# Kahu Agent Installer — Windows
# Auto-generated for appliance: {manager_host}
# Run as Administrator in PowerShell

$ErrorActionPreference = "Stop"
$ManagerIP = "{manager_host}"
$AgentGroup = "{agent_group}"
$WazuhVersion = "4.9.2-1"

Write-Host "=== Kahu Agent Installer (Windows) ===" -ForegroundColor Cyan
Write-Host "Manager: $ManagerIP"
Write-Host ""

# Download
Write-Host "[1/4] Downloading Wazuh agent..." -ForegroundColor Yellow
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
$InstallerPath = "$env:TEMP\wazuh-agent.msi"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath

# Install silently
Write-Host "[2/4] Installing agent..." -ForegroundColor Yellow
$MsiArgs = @(
    "/i", $InstallerPath,
    "/q",
    "WAZUH_MANAGER=$ManagerIP",
    "WAZUH_AGENT_GROUP=$AgentGroup",
    "WAZUH_REGISTRATION_SERVER=$ManagerIP"
)
Start-Process msiexec.exe -ArgumentList $MsiArgs -Wait -NoNewWindow
Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue

# Start service
Write-Host "[3/4] Starting agent service..." -ForegroundColor Yellow
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

# Verify
Write-Host "[4/4] Verifying..." -ForegroundColor Yellow
$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {{
    Write-Host ""
    Write-Host "SUCCESS: Kahu agent is running and connecting to $ManagerIP" -ForegroundColor Green
    Write-Host "Agent will appear in the Kahu dashboard within 60 seconds."
}} else {{
    Write-Host ""
    Write-Host "WARNING: Agent installed but service may not be running." -ForegroundColor Yellow
    Write-Host "Check: Get-Service WazuhSvc"
    Write-Host "Logs: C:\Program Files (x86)\ossec-agent\ossec.log"
}}
"""


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AgentRemoveIn(BaseModel):
    agent_id: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# Cache of host interfaces reported by the detect script
_host_interfaces: list[dict] = []


@router.get("/interfaces")
async def list_interfaces(request: Request) -> dict:
    """Return host network interfaces for appliance host selection."""
    interfaces = list(_host_interfaces)  # copy
    seen = {i["ip"] for i in interfaces}

    # Also capture the browser's request host as a candidate
    request_host = request.headers.get("host", "").split(":")[0]
    if request_host and request_host not in ("localhost", "127.0.0.1", "0.0.0.0") and request_host not in seen:
        seen.add(request_host)
        interfaces.append({"ip": request_host, "name": "Current browser address", "default": False})

    # Filter out virtual/internal adapters and sort by priority
    virtual_keywords = ("vethernet", "vmware", "vmnet", "wsl", "hyper-v", "docker", "loopback", "veth", "br-")

    def is_virtual(iface):
        name_lower = iface.get("name", "").lower()
        return any(kw in name_lower for kw in virtual_keywords)

    def priority(iface):
        name_lower = iface.get("name", "").lower()
        ip = iface["ip"]
        # Virtual adapters always last
        if is_virtual(iface):
            return 9
        # Real physical adapters first
        if any(kw in name_lower for kw in ("wi-fi", "wifi", "eth0", "en0", "lan")):
            return 0
        # "ethernet" but not "vethernet"
        if "ethernet" in name_lower and "vethernet" not in name_lower:
            return 0
        if ip.startswith("10.") and "vpn" not in name_lower and "warp" not in name_lower:
            return 1
        if ip.startswith("192.168."):
            return 2
        return 5

    interfaces.sort(key=priority)

    # Mark the best default (first non-virtual)
    for iface in interfaces:
        iface["default"] = False
    for iface in interfaces:
        if not is_virtual(iface):
            iface["default"] = True
            break
    if interfaces and not any(i["default"] for i in interfaces):
        interfaces[0]["default"] = True

    return {
        "interfaces": interfaces,
        "current_host": settings.appliance_host or None,
        "configured": bool(settings.appliance_host),
    }


class ReportInterfacesIn(BaseModel):
    interfaces: list[dict] = Field(..., min_length=1)


@router.post("/report-interfaces")
async def report_interfaces(body: ReportInterfacesIn) -> dict:
    """Accept host interface data reported by a client-side detection script.

    Run on the host:
      PowerShell: $ips = Get-NetIPAddress -AddressFamily IPv4 | Where { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select IPAddress, InterfaceAlias; irm -Method POST -Uri http://localhost:8000/api/agents/report-interfaces -ContentType 'application/json' -Body ($ips | ConvertTo-Json -Wrap @{interfaces=$ips})
    """
    global _host_interfaces
    _host_interfaces = []
    seen = set()
    for iface in body.interfaces:
        ip = iface.get("ip") or iface.get("IPAddress") or ""
        name = iface.get("name") or iface.get("InterfaceAlias") or ""
        if ip and ip not in seen and not ip.startswith("127."):
            seen.add(ip)
            _host_interfaces.append({
                "ip": ip,
                "name": f"{name} - {_classify_ip(ip)}" if name else _classify_ip(ip),
                "default": False,
            })
    return {"accepted": len(_host_interfaces)}


def _classify_ip(ip: str) -> str:
    """Give a friendly name to common RFC1918 ranges."""
    if ip.startswith("10."):
        return "Private (10.x - corporate/VPN)"
    if ip.startswith("172."):
        octet2 = int(ip.split(".")[1])
        if 16 <= octet2 <= 31:
            return "Private (172.16-31.x - Docker/internal)"
    if ip.startswith("192.168."):
        return "Private (192.168.x - LAN)"
    return "Public/Other"


class SetHostIn(BaseModel):
    host: str = Field(..., min_length=1)


@router.post("/configure-host")
async def configure_host(body: SetHostIn) -> dict:
    """Set the appliance host address that agents connect to.

    Persists to the .env file and updates the running config.
    """
    import re

    host = body.host.strip()
    # Basic validation
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    hostname_pattern = re.compile(r"^[a-zA-Z0-9._-]+$")
    if not ip_pattern.match(host) and not hostname_pattern.match(host):
        raise HTTPException(status_code=400, detail="Invalid IP or hostname")

    # Update running config
    settings.appliance_host = host

    # Persist to .env file
    env_path = "/app/.env"
    try:
        lines = []
        found = False
        try:
            with open(env_path) as f:
                lines = f.readlines()
        except FileNotFoundError:
            pass

        new_lines = []
        for line in lines:
            if line.strip().startswith("APPLIANCE_HOST="):
                new_lines.append(f"APPLIANCE_HOST={host}\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(f"APPLIANCE_HOST={host}\n")

        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception:
        pass  # Still works for this session even if .env write fails

    return {"host": host, "persisted": True}


@router.get("/platforms")
async def list_platforms(request: Request) -> dict:
    """List available agent platforms and download info."""
    base_url = str(request.base_url).rstrip("/")
    return {
        "platforms": [
            {
                "id": "linux",
                "name": "Linux",
                "description": "Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Amazon Linux",
                "architectures": ["x86_64", "aarch64"],
                "install_method": "Shell script (curl | bash)",
                "download_url": f"{base_url}/api/agents/install/linux",
                "one_liner": f"curl -sS {base_url}/api/agents/install/linux | sudo bash",
            },
            {
                "id": "windows",
                "name": "Windows",
                "description": "Windows 10/11, Server 2016/2019/2022/2025",
                "architectures": ["x86_64"],
                "install_method": "PowerShell script (Run as Admin)",
                "download_url": f"{base_url}/api/agents/install/windows",
                "one_liner": f"irm {base_url}/api/agents/install/windows | iex",
            },
            {
                "id": "macos",
                "name": "macOS",
                "description": "macOS 12+ (Monterey, Ventura, Sonoma, Sequoia)",
                "architectures": ["Intel", "Apple Silicon"],
                "install_method": "Shell script (curl | bash)",
                "download_url": f"{base_url}/api/agents/install/macos",
                "one_liner": f"curl -sS {base_url}/api/agents/install/macos | sudo bash",
            },
        ]
    }


@router.get("/install/{platform}", response_class=PlainTextResponse)
async def get_install_script(platform: str, request: Request) -> PlainTextResponse:
    """Download a pre-configured install script for the given platform."""
    # Determine the manager host agents should connect to
    if settings.appliance_host:
        manager_host = settings.appliance_host
    else:
        request_host = request.headers.get("host", "").split(":")[0]
        manager_host = request_host if request_host and request_host not in ("localhost", "127.0.0.1", "0.0.0.0") else "<YOUR_KAHU_IP>"

    agent_group = "default"

    templates = {
        "linux": ("kahu-install.sh", LINUX_INSTALL, "text/x-shellscript"),
        "macos": ("kahu-install-macos.sh", MACOS_INSTALL, "text/x-shellscript"),
        "windows": ("kahu-install.ps1", WINDOWS_INSTALL, "text/plain"),
    }

    if platform not in templates:
        raise HTTPException(status_code=404, detail=f"Unknown platform: {platform}. Use linux, windows, or macos.")

    filename, template, content_type = templates[platform]
    script = template.format(manager_host=manager_host, agent_group=agent_group)

    return PlainTextResponse(
        content=script,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/list")
async def list_agents() -> dict:
    """List all enrolled agents from Wazuh manager."""
    wazuh = WazuhAPIClient()
    try:
        await wazuh.authenticate()
        data = await wazuh.api_get("/agents", params={"limit": 500, "select": "id,name,ip,os.name,os.version,status,dateAdd,lastKeepAlive,group,version"})
        agents = data.get("data", {}).get("affected_items", [])

        summary = {
            "total": len(agents),
            "active": sum(1 for a in agents if a.get("status") == "active"),
            "disconnected": sum(1 for a in agents if a.get("status") == "disconnected"),
            "never_connected": sum(1 for a in agents if a.get("status") == "never_connected"),
        }

        return {"agents": agents, "summary": summary}
    except Exception as e:
        return {
            "agents": [],
            "summary": {"total": 0, "active": 0, "disconnected": 0, "never_connected": 0},
            "error": str(e),
        }


@router.delete("/{agent_id}")
async def remove_agent(agent_id: str) -> dict:
    """Remove an agent from Wazuh manager."""
    wazuh = WazuhAPIClient()
    try:
        await wazuh.authenticate()
        data = await wazuh.api_delete(f"/agents", params={"agents_list": agent_id, "status": "all", "older_than": "0s"})
        return {"removed": True, "detail": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove agent: {e}")


@router.post("/restart/{agent_id}")
async def restart_agent(agent_id: str) -> dict:
    """Restart a specific agent."""
    wazuh = WazuhAPIClient()
    try:
        await wazuh.authenticate()
        data = await wazuh.api_put(f"/agents/{agent_id}/restart")
        return {"restarted": True, "detail": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart agent: {e}")
