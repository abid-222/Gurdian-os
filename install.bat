@echo off
REM Smart OS Guardian - one-time setup (Windows 10/11, Python 3.10+ required)
setlocal
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% --version >nul 2>nul || (echo Python 3.10+ not found. Install from https://www.python.org/downloads/ and tick "Add to PATH". & pause & exit /b 1)
echo [1/3] Creating virtual environment .venv ...
%PY% -m venv .venv || (echo venv failed & pause & exit /b 1)
echo [2/3] Installing dependencies ...
call .venv\Scripts\python -m pip install --upgrade pip >nul
call .venv\Scripts\python -m pip install -r requirements.txt || (echo pip install failed & pause & exit /b 1)
echo [3/3] Running self-tests ...
call .venv\Scripts\python -m pip install -q pytest httpx
call .venv\Scripts\python -m pytest -q tests
call .venv\Scripts\python -c "import sys; sys.path.insert(0,'agent/python-agent'); from guardian import selfcheck; sys.exit(selfcheck.main())"
echo.
echo Done. Start with run.bat   (run_admin.bat for Security log + full process details)
echo Next: put a dataset in datasets\ and press Train in Model Lab. Optional: autostart_install.bat, deployment\installer\install_sysmon.ps1 (admin)
pause
