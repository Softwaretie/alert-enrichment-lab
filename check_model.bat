@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Model test

if not exist ".venv\Scripts\python.exe" (
    echo Setup has not been run yet. Double-click setup.bat first.
    echo.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" scripts\check_model.py
echo.
pause
