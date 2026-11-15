@echo off
REM Removes the autostart task. "uninstall.bat purge" also deletes .venv and ALL local Guardian data.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File deployment\installer\autostart.ps1 -Remove
if /i "%1"=="purge" (
  rmdir /s /q .venv 2>nul
  rmdir /s /q data 2>nul
  rmdir /s /q "%LOCALAPPDATA%\SmartOSGuardian" 2>nul
  rmdir /s /q "%ProgramData%\SmartOSGuardian" 2>nul
)
echo Uninstalled. (Sysmon, if you installed it, is separate: sysmon64 -u)
pause
