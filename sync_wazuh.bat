@echo off
title Sync Live Wazuh Alerts to Vercel
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync_wazuh.ps1"

pause
