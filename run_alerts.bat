@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Checking mailbox

if not exist ".venv\Scripts\python.exe" (
    echo Setup has not been run yet. Double-click setup.bat first.
    echo.
    pause
    exit /b 1
)

echo Checking your mailbox for reported emails ...
echo (The first time, your browser opens so you can sign in to Google.)
echo.
rem Any options you type after the file name are passed along, e.g.:
rem     run_alerts.bat --no-gmail      run_alerts.bat --max-results 5
".venv\Scripts\python.exe" main.py %*
set "EXITCODE=%errorlevel%"

echo.
if not "%EXITCODE%"=="0" (
    echo Something went wrong - the lines above say what. check_setup.bat can help too.
) else (
    echo Done. Double-click run_dashboard.bat to see the results.
)
echo.
pause
exit /b %EXITCODE%
