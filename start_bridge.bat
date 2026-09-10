@echo off
title Wazuh Attack Correlator - Zero-VPN Bridge
cd /d "%~dp0"

echo ============================================================
echo   Starting Wazuh Zero-VPN Cloudflare Bridge
echo ============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_bridge.ps1"

pause
