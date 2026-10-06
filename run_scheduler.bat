@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Nightly scheduler

if not exist ".venv\Scripts\python.exe" (
    echo Setup has not been run yet. Double-click setup.bat first.
    echo.
    pause
    exit /b 1
)

echo Starting the nightly scheduler. It checks your mailbox once a day
echo (2 AM by default; change BATCH_SCHEDULE_HOUR in .env).
echo Leave this window open; close it to stop. Your PC must be on and awake.
echo.
".venv\Scripts\python.exe" scripts\scheduler.py
echo.
pause
