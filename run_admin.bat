@echo off
REM Same as run.bat but elevated (needed for the Security event log and some process details). UAC prompt will appear.
powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~dp0run.bat' -WorkingDirectory '%~dp0'"
