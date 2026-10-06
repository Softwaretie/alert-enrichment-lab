@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Setup has not been run yet. Double-click setup.bat first.
    echo.
    pause
    exit /b 1
)

echo Starting Alert Enrichment Dashboard...
echo (A second window opens for the server. Leave it open; close it to stop.)
start "Alert Enrichment Dashboard" ".venv\Scripts\python.exe" dashboard\app.py
timeout /t 2 /nobreak >nul
start "" http://localhost:5000
