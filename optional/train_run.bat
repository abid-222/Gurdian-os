@echo off
REM Command-line training (the Train button in Model Lab does the same). Example: train_run.bat --source auto --max-rows 100000
cd /d "%~dp0"
.venv\Scripts\python ai\malware-pe\train.py %*
pause
