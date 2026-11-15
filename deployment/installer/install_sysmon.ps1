# Installs/updates Sysmon with Guardian's selective config. Needs an ELEVATED PowerShell and internet once (Sysinternals).
#   powershell -ExecutionPolicy Bypass -File deployment\installer\install_sysmon.ps1
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Run this from an Administrator PowerShell."; exit 1 }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cfg = Join-Path $root "deployment\sysmon-config\guardian-sysmon.xml"
$dir = Join-Path $env:ProgramData "SmartOSGuardian\sysmon"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$zip = Join-Path $dir "Sysmon.zip"
Write-Host "Downloading Sysmon from Sysinternals ..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $dir -Force
$exe = if ([Environment]::Is64BitOperatingSystem) { Join-Path $dir "Sysmon64.exe" } else { Join-Path $dir "Sysmon.exe" }
$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft") { Write-Error "Sysmon signature check failed: $($sig.Status)"; exit 1 }
$installed = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue
if ($installed) { & $exe -accepteula -c $cfg } else { & $exe -accepteula -i $cfg }
net localgroup "Event Log Readers" $env:USERNAME /add 2>$null | Out-Null   # lets a non-admin Guardian read the logs after next sign-in
Write-Host "Sysmon ready. Sign out/in once, then restart Guardian: 'sysmon' should show as available."
