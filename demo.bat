@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Demo

echo This demo needs NO accounts and NO API keys. It builds harmless fake
echo "attachments" in memory and shows how the analyzer judges each one.
echo Nothing is saved to disk, uploaded, or run.
echo.

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" scripts\demo.py
) else (
    py -3 scripts\demo.py 2>nul || python scripts\demo.py
)
if errorlevel 1 (
    echo.
    echo The demo needs Python 3.10 or newer. See docs\SETUP_GUIDE.md, step 1.
)
echo.
pause
