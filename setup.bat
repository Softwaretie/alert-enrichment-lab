@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Alert Enrichment - Setup

echo ================================================================
echo   Alert Enrichment - one-time setup
echo ================================================================
echo.
echo This will:
echo   1. Make a private Python environment inside this folder (.venv)
echo   2. Install the packages the project needs
echo   3. Walk you through entering your API keys
echo.
echo Nothing is installed outside this folder except your saved keys,
echo which go into Windows Credential Manager. You can re-run this
echo any time; it is safe.
echo.
pause

rem ---- Step 1: find a Python that is 3.10 or newer --------------------
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if not errorlevel 1 set "PY=python"
)
if not defined PY goto :nopython

echo.
echo [1/3] Found Python:
%PY% --version

rem ---- Step 2: private environment + packages -------------------------
if exist ".venv\Scripts\python.exe" (
    echo       Using the existing .venv folder.
) else (
    echo       Creating the private environment .venv ...
    %PY% -m venv .venv
    if errorlevel 1 goto :venvfail
)

echo.
echo [2/3] Installing packages (this can take a minute or two) ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :pipfail

rem ---- Step 3: keys ---------------------------------------------------
echo.
echo [3/3] Entering your API keys.
echo       Have these ready: docs\SETUP_GUIDE.md shows where to get each one.
echo       You can press Enter to skip any and come back later.
echo.
pause
".venv\Scripts\python.exe" scripts\setup_secrets.py

echo.
echo ================================================================
echo   Checking everything ...
echo ================================================================
".venv\Scripts\python.exe" scripts\check_setup.py

echo.
echo ----------------------------------------------------------------
echo   Setup finished. What to do next:
echo     demo.bat            see it work right now (no keys needed)
echo     run_alerts.bat      check your mailbox for reported emails
echo     run_dashboard.bat   open the results page
echo     check_setup.bat     re-run the health check if something breaks
echo ----------------------------------------------------------------
echo.
pause
exit /b 0

:nopython
echo.
echo ================================================================
echo   Python 3.10 or newer was not found on this computer.
echo ================================================================
echo.
echo Easiest fix: open the Start menu, type  cmd , press Enter, then run:
echo.
echo     winget install Python.Python.3.12
echo.
echo Then CLOSE this window and double-click setup.bat again.
echo.
echo No winget? Download Python from https://www.python.org/downloads/
echo and TICK the box "Add python.exe to PATH" on the first installer
echo screen. If Windows opens the Microsoft Store when you type python,
echo that is the same problem: Python is not installed yet.
echo.
pause
exit /b 1

:venvfail
echo.
echo Could not create the private environment (.venv).
echo If a folder named .venv already exists and is broken, rename or delete
echo it and run setup.bat again. More help: docs\SETUP_GUIDE.md
echo.
pause
exit /b 1

:pipfail
echo.
echo Installing the packages failed. The messages above say why. Common causes:
echo   - no internet connection, or a company network blocking pip
echo   - an old Python (run: py -3 --version)
echo Fix that, then run setup.bat again. More help: docs\SETUP_GUIDE.md
echo.
pause
exit /b 1
