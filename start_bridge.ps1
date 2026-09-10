# Zero-VPN Bridge Launcher for Wazuh Attack Correlator
# Connects your local Wazuh (172.16.20.62) to your Vercel frontend without a VPN.

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Correlator - Zero-VPN Cloudflare Bridge Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# 1. Check Python
$pyCmd = Get-Command py, python -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pyCmd) {
    Write-Host "[!] Error: Python was not found in PATH." -ForegroundColor Red
    exit 1
}

# 2. Check cloudflared.exe
$cloudflared = Join-Path $root ".tools\cloudflared.exe"
if (-not (Test-Path $cloudflared)) {
    Write-Host "[!] Error: cloudflared.exe not found at $cloudflared" -ForegroundColor Red
    exit 1
}

# 3. Test local Wazuh connection
Write-Host "[*] Checking Wazuh connection on LAN..." -ForegroundColor Yellow
$testOutput = & $pyCmd.Name -m correlation_tool.cli --test-wazuh 2>&1 | Out-String
if ($testOutput -match '"indexer_connected":\s*true' -or $testOutput -match '"success":\s*true') {
    Write-Host "[OK] Wazuh Indexer is reachable on local network!" -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Wazuh not reachable yet. Proceeding anyway..." -ForegroundColor Yellow
}

# 4. Start local server on port 8000 if not already running
$port = 8000
$portInUse = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
$serverProc = $null

if (-not $portInUse) {
    Write-Host "[*] Starting local backend server on port $port..." -ForegroundColor Yellow
    $serverArgs = @("-m", "correlation_tool.server", "$port")
    $serverProc = Start-Process -FilePath $pyCmd.Source -ArgumentList $serverArgs -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1
} else {
    Write-Host "[*] Local backend server already running on port $port." -ForegroundColor Green
}

# 5. Start cloudflared tunnel
$logFile = Join-Path $root ".cloudflared.log"
if (Test-Path $logFile) {
    Remove-Item -Force $logFile -ErrorAction SilentlyContinue
}

Write-Host "[*] Launching Cloudflare Tunnel (protocol: http2, zero VPN)..." -ForegroundColor Yellow
$cfArgs = @("tunnel", "--protocol", "http2", "--logfile", $logFile, "--url", "http://localhost:$port")
$cfProc = Start-Process -FilePath $cloudflared -ArgumentList $cfArgs -PassThru -WindowStyle Hidden

Write-Host "[*] Waiting for tunnel URL..." -ForegroundColor Yellow
$tunnelUrl = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $logFile) {
        $content = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($content -match '(https://[a-zA-Z0-9-]+\.trycloudflare\.com)') {
            $tunnelUrl = $matches[1]
            break
        }
    }
}

if ($tunnelUrl) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " [OK] ZERO-VPN BRIDGE IS ACTIVE!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Public Bridge URL: " -NoNewline
    Write-Host "$tunnelUrl" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  How to use with your Vercel Frontend:" -ForegroundColor Cyan
    Write-Host "  1. Open your Vercel frontend in your browser."
    Write-Host "  2. Click 'Settings' (gear icon)."
    Write-Host "  3. Paste the URL above into 'Backend / Bridge API URL'."
    Write-Host "  4. Click 'Save Settings'."
    Write-Host "  5. Click 'Sync Live Wazuh' - live logs will load!" -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop the bridge when finished." -ForegroundColor Gray

    try {
        while (-not $cfProc.HasExited) {
            Start-Sleep -Seconds 2
        }
    } finally {
        Write-Host "`n[*] Shutting down bridge..." -ForegroundColor Yellow
        if ($cfProc -and -not $cfProc.HasExited) {
            Stop-Process -Id $cfProc.Id -Force -ErrorAction SilentlyContinue
        }
        if ($serverProc -and -not $serverProc.HasExited) {
            Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[OK] Bridge stopped." -ForegroundColor Green
    }
} else {
    Write-Host "[!] Could not obtain Cloudflare tunnel URL. Inspect $logFile for details." -ForegroundColor Red
    if ($cfProc -and -not $cfProc.HasExited) {
        Stop-Process -Id $cfProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    }
}
