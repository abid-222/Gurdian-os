# Registers Guardian to start at logon (per-user scheduled task, no admin needed) and restart if it crashes.
#   powershell -ExecutionPolicy Bypass -File deployment\installer\autostart.ps1          (add)
#   powershell -ExecutionPolicy Bypass -File deployment\installer\autostart.ps1 -Remove  (remove)
param([switch]$Remove)
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$task = "SmartOSGuardian"
if ($Remove) { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "Autostart removed."; exit }
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "Run install.bat first (.venv missing)."; exit 1 }
# PYTHONPATH must live inside the task itself (a variable set in this script never reaches it), so go through cmd /c.
$arg = "/c set PYTHONPATH=$root\agent\python-agent&& `"$py`" -m guardian.main --no-ui"
$act = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $arg -WorkingDirectory $root
$trg = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$set = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg -Settings $set -Description "Smart OS Guardian agent (loopback only)" -RunLevel Limited -Force | Out-Null
Write-Host "Autostart registered (runs at logon, restarts up to 3 times if it crashes)."
