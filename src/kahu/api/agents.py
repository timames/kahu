"""Agent deployment scripts — served with APPLIANCE_HOST baked in."""

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from kahu.config import settings

router = APIRouter()

WAZUH_VERSION = "4.14.1"


@router.get("/install.ps1", response_class=PlainTextResponse)
async def agent_install_windows():
    """Download a PowerShell script that installs the Wazuh agent on Windows."""
    host = settings.appliance_host or "MANAGER_IP"
    return PlainTextResponse(
        _windows_script(host),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="kahu-agent-install.ps1"'},
    )


@router.get("/install.sh", response_class=PlainTextResponse)
async def agent_install_linux():
    """Download a bash script that installs the Wazuh agent on Linux/macOS."""
    host = settings.appliance_host or "MANAGER_IP"
    return PlainTextResponse(
        _linux_script(host),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="kahu-agent-install.sh"'},
    )


def _windows_script(manager: str) -> str:
    return f'''\
# Kahu — Install Wazuh Agent (Windows)
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File kahu-agent-install.ps1
#
# Optional overrides:
#   -Manager 10.0.0.5       (defaults to appliance host)
#   -AgentName MYPC          (defaults to hostname)

param(
    [string]$Manager = "{manager}",
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$Version = "{WAZUH_VERSION}"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Error "Run this script as Administrator."
    exit 1
}}

$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi"
$installerPath = "$env:TEMP\\wazuh-agent.msi"

Write-Host "[1/4] Downloading Wazuh agent $Version ..." -ForegroundColor Cyan
if (Test-Path $installerPath) {{ Remove-Item $installerPath }}
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

Write-Host "[2/4] Installing Wazuh agent ..." -ForegroundColor Cyan
Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn WAZUH_MANAGER=`"$Manager`" WAZUH_AGENT_NAME=`"$AgentName`" WAZUH_REGISTRATION_SERVER=`"$Manager`"" -Wait -NoNewWindow

Write-Host "[3/4] Starting Wazuh service ..." -ForegroundColor Cyan
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

Write-Host "[4/4] Verifying ..." -ForegroundColor Cyan
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {{
    Write-Host "Wazuh agent installed and running. Manager: $Manager" -ForegroundColor Green
}} else {{
    Write-Warning "Service not running. Check C:\\Program Files (x86)\\ossec-agent\\ossec.log"
}}

Remove-Item $installerPath -ErrorAction SilentlyContinue
'''


def _linux_script(manager: str) -> str:
    return f'''\
#!/usr/bin/env bash
# Kahu — Install Wazuh Agent (Linux / macOS)
# Usage:
#   curl -sO https://YOUR_KAHU_HOST/api/agents/install.sh
#   sudo bash install.sh
#
# Optional overrides:
#   -m MANAGER_IP   (defaults to appliance host)
#   -n AGENT_NAME   (defaults to hostname)

set -euo pipefail

MANAGER="{manager}"
AGENT_NAME="$(hostname)"
VERSION="{WAZUH_VERSION}"

while getopts "m:n:v:" opt; do
    case $opt in
        m) MANAGER="$OPTARG" ;;
        n) AGENT_NAME="$OPTARG" ;;
        v) VERSION="$OPTARG" ;;
        *) echo "Usage: sudo bash $0 [-m MANAGER_IP] [-n AGENT_NAME] [-v VERSION]"; exit 1 ;;
    esac
done

if [ -z "$MANAGER" ] || [ "$MANAGER" = "MANAGER_IP" ]; then
    echo "Error: Manager address not configured. Pass -m MANAGER_IP"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo"
    exit 1
fi

OS="$(uname -s)"

echo "[1/4] Installing Wazuh agent $VERSION ..."

if [ "$OS" = "Linux" ]; then
    if [ -f /etc/debian_version ]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update -qq
        WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y -qq wazuh-agent="$VERSION-1"
    elif [ -f /etc/redhat-release ]; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo << YUMEOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
YUMEOF
        WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" yum install -y -q "wazuh-agent-$VERSION-1"
    else
        echo "Unsupported Linux distro. Install manually: https://documentation.wazuh.com"
        exit 1
    fi
elif [ "$OS" = "Darwin" ]; then
    curl -so /tmp/wazuh-agent.pkg "https://packages.wazuh.com/4.x/macos/wazuh-agent-${{VERSION}}-1.intel64.pkg"
    WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" installer -pkg /tmp/wazuh-agent.pkg -target /
    rm -f /tmp/wazuh-agent.pkg
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "[2/4] Configuring agent ..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    sed -i.bak "s|<address>.*</address>|<address>$MANAGER</address>|g" "$OSSEC_CONF"
fi

echo "[3/4] Starting Wazuh agent ..."
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
elif [ "$OS" = "Darwin" ]; then
    /Library/Ossec/bin/wazuh-control start
else
    /var/ossec/bin/wazuh-control start
fi

sleep 3

echo "[4/4] Verifying ..."
if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet wazuh-agent; then
        echo "Wazuh agent installed and running. Manager: $MANAGER"
    else
        echo "Warning: service not running. Check /var/ossec/logs/ossec.log"
    fi
else
    if /var/ossec/bin/wazuh-control status | grep -q "running"; then
        echo "Wazuh agent installed and running. Manager: $MANAGER"
    else
        echo "Warning: service not running. Check /var/ossec/logs/ossec.log"
    fi
fi
'''
