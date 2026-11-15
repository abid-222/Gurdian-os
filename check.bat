@echo off
REM Basic health check: dependencies, loopback port, database, policy, telemetry sources.
cd /d "%~dp0"
set PYTHONPATH=%~dp0agent\python-agent
.venv\Scripts\python -m guardian.selfcheck
pause
