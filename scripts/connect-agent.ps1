# Connect local Wazuh agent to Kahu's dockerized manager
# Right-click > Run with PowerShell (as Administrator)

$ErrorActionPreference = "Stop"
$agentDir = "C:\Program Files (x86)\ossec-agent"
$conf = "$agentDir\ossec.conf"
$log = "$agentDir\ossec.log"

if (-not (Test-Path $agentDir)) {
    Write-Host "Wazuh agent not found at $agentDir" -ForegroundColor Red
    exit 1
}

Write-Host "Stopping Wazuh agent..." -ForegroundColor Yellow
net stop WazuhSvc 2>$null

Write-Host "Updating manager address to 127.0.0.1..." -ForegroundColor Yellow
(Get-Content $conf -Raw) -replace '<address>[^<]*</address>', '<address>127.0.0.1</address>' | Set-Content $conf -NoNewline

Write-Host "Starting Wazuh agent..." -ForegroundColor Yellow
net start WazuhSvc

Start-Sleep -Seconds 5

Write-Host "`nAgent log (last 20 lines):" -ForegroundColor Cyan
Get-Content $log -Tail 20

Write-Host "`nDone. Agent should auto-enroll and start sending events." -ForegroundColor Green
Write-Host "Verify with: docker exec kuahene-wazuh-manager-1 bash -c '//var/ossec/bin/agent_control -l'"
pause
