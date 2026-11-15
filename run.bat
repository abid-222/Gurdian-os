@echo off
REM Starts the Guardian agent + local API and opens the desktop shell. Loopback only, no internet needed.
cd /d "%~dp0"
set PYTHONPATH=%~dp0agent\python-agent
if exist .venv\Scripts\python.exe (
    set PY=.venv\Scripts\python.exe
) else (
    where python >nul 2>nul && (set PY=python) || (echo Python not found. Run install.bat first. & pause & exit /b 1)
)
%PY% -m guardian.main %*
pause
