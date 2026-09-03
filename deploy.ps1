# Wazuh Attack Correlator Deployment Script
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Attack Correlator Deployment" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

$port = 8000
if ($args.Count -gt 0) {
    $port = [int]$args[0]
}

# 1. Verify Python
$pyCmd = Get-Command py, python -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pyCmd) {
    Write-Host "[!] Error: Python was not found in PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Using Python: $($pyCmd.Source)" -ForegroundColor Green

# 2. Run Tests
Write-Host "[*] Running test suite..." -ForegroundColor Yellow
& $pyCmd.Name -m unittest discover tests
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Unit tests failed. Aborting deployment." -ForegroundColor Red
    exit 1
}
Write-Host "[*] All unit tests passed." -ForegroundColor Green

# 3. Test Wazuh Connection
Write-Host "[*] Testing Wazuh connection..." -ForegroundColor Yellow
& $pyCmd.Name -m correlation_tool.cli --test-wazuh

# 4. Start Server
Write-Host ""
Write-Host "[*] Starting production server on port $port..." -ForegroundColor Green
Write-Host "[*] Dashboard URL: http://localhost:$port" -ForegroundColor Cyan
Start-Process "http://localhost:$port"
& $pyCmd.Name -m correlation_tool.server $port
