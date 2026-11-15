@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File deployment\installer\autostart.ps1
pause
