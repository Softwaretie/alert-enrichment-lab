@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Setup check

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" scripts\check_setup.py
) else (
    echo No .venv folder yet - setup.bat has not been run. Checking with system Python:
    echo.
    py -3 scripts\check_setup.py 2>nul || python scripts\check_setup.py
)
echo.
pause
