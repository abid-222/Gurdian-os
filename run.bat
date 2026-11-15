@echo off
REM Starts the Guardian agent + local API and opens the desktop shell. Loopback only, no internet needed.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run install.bat first. & pause & exit /b 1)
set PYTHONPATH=%~dp0agent\python-agent
.venv\Scripts\python -m guardian.main %*
pause
