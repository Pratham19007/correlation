param(
    [switch]$Loop,
    [int]$IntervalSeconds = 60
)

# Live Wazuh Alert Syncer
# Fetches live alerts from Wazuh (172.16.20.62) and updates Vercel / GitHub automatically (Zero VPN).

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Live Alert Syncer (Zero VPN)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$pyCmd = Get-Command py, python -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pyCmd) {
    Write-Host "[!] Error: Python not found." -ForegroundColor Red
    exit 1
}

function Do-Sync {
    Write-Host "[*] Fetching latest live alerts from Wazuh (https://172.16.20.62:9200)..." -ForegroundColor Yellow

    $code = @"
import json
from correlation_tool.wazuh_client import WazuhClient

client = WazuhClient.from_config()
alerts = client.fetch_alerts(limit=1000)
if alerts:
    with open('live_wazuh_alerts.json', 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)
    print(f'[OK] Ingested {len(alerts)} live security alerts from Wazuh.')
else:
    print('[!] Could not fetch alerts from Wazuh.')
"@

    & $pyCmd.Source -c $code

    if (Test-Path "live_wazuh_alerts.json") {
        $diff = git status --porcelain live_wazuh_alerts.json
        if ($diff) {
            Write-Host "[*] New alerts detected. Pushing to GitHub for Vercel..." -ForegroundColor Yellow
            git add live_wazuh_alerts.json
            git commit -m "Sync live Wazuh security alerts"
            git push origin master
            Write-Host ""
            Write-Host "============================================================" -ForegroundColor Green
            Write-Host " [OK] SYNC COMPLETE! Vercel is now deploying latest logs." -ForegroundColor Green
            Write-Host "============================================================" -ForegroundColor Green
        } else {
            Write-Host "[OK] Alerts in project are already up to date with Wazuh SIEM." -ForegroundColor Green
        }
    } else {
        Write-Host "[!] Failed to generate live_wazuh_alerts.json." -ForegroundColor Red
    }
}

if ($Loop) {
    Write-Host "[*] Live Watch Mode Active: Checking for new Wazuh alerts every $IntervalSeconds s..." -ForegroundColor Magenta
    Write-Host "    (Press Ctrl+C anytime to stop)" -ForegroundColor Gray
    while ($true) {
        Do-Sync
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    Do-Sync
}
