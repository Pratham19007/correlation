@echo off
echo ===================================================
echo   Starting Wazuh Attack Correlator Server
echo ===================================================
echo.

where py >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Python launcher found. Starting server on port 8000...
    start http://localhost:8000
    py -m correlation_tool.server 8000
    goto end
)

where python >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Python found. Starting server on port 8000...
    start http://localhost:8000
    python -m correlation_tool.server 8000
    goto end
)

echo [!] Error: Python is not installed or not in PATH.
pause

:end
