@echo off
title Wazuh Alert Syncer for Vercel
cd /d "%~dp0"

echo ============================================================
echo   Wazuh SIEM - Live Alert Sync to Project (Zero VPN)
echo ============================================================
echo.
echo [1] Sync once now and push to Vercel
echo [2] Auto-sync continuously every 60 seconds (Live Watch Mode)
echo.
set /p choice="Enter choice [1 or 2, default 1]: "
if "%choice%"=="2" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync_wazuh.ps1" -Loop
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync_wazuh.ps1"
)

pause
