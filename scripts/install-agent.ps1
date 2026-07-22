#Requires -RunAsAdministrator
# Connect existing Wazuh agent to Kahu's dockerized manager
# Right-click > Run with PowerShell (as Administrator)

$ErrorActionPreference = "Stop"
$agentDir = "C:\Program Files (x86)\ossec-agent"
$conf = "$agentDir\ossec.conf"
$log = "$agentDir\ossec.log"

Write-Host "=== Kahu Wazuh Agent Setup ===" -ForegroundColor Cyan

if (-not (Test-Path $agentDir)) {
    Write-Host "Wazuh agent not found at $agentDir" -ForegroundColor Red
    exit 1
}

# Stop the agent
Write-Host "`nStopping Wazuh agent..." -ForegroundColor Yellow
net stop WazuhSvc 2>$null

# Update manager address to localhost
Write-Host "Setting manager address to 127.0.0.1..." -ForegroundColor Yellow
(Get-Content $conf -Raw) -replace '<address>[^<]*</address>', '<address>127.0.0.1</address>' | Set-Content $conf -NoNewline

# Start the agent — it will auto-enroll via port 1515
Write-Host "Starting Wazuh agent..." -ForegroundColor Yellow
net start WazuhSvc

Start-Sleep -Seconds 10

# Show logs
Write-Host "`nAgent log (last 20 lines):" -ForegroundColor Cyan
Get-Content $log -Tail 20 -ErrorAction SilentlyContinue

Write-Host "`nDone. Verify with:" -ForegroundColor Green
Write-Host "  docker exec kuahene-wazuh-manager-1 bash -c '//var/ossec/bin/agent_control -l'" -ForegroundColor White
pause
