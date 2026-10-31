#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds WinGuardian and installs it: the monitoring service (LocalSystem, auto-start, restart on failure)
    plus the tray icon (starts at logon for every user).
    Re-running the script upgrades an existing install; the baseline database is kept.
#>
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WinGuardian')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$serviceName = 'WinGuardian'
$serviceExe = Join-Path $InstallDir 'Service\WinGuardian.Service.exe'
$trayExe = Join-Path $InstallDir 'Tray\WinGuardian.Tray.exe'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Tell the service's self-protection that the coming stop/file changes are a planned upgrade (valid 15 minutes).
New-Item -Path 'HKLM:\SOFTWARE\WinGuardian' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WinGuardian' -Name 'MaintenanceUntilUtc' -Value ([DateTime]::UtcNow.AddMinutes(15).ToString('o'))

Write-Host 'Stopping any running instance...'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
Get-Process -Name 'WinGuardian.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host 'Publishing...'
dotnet publish (Join-Path $repo 'src\WinGuardian.Service\WinGuardian.Service.csproj') -c Release -o (Join-Path $InstallDir 'Service')
if ($LASTEXITCODE -ne 0) { throw 'Service publish failed.' }
dotnet publish (Join-Path $repo 'src\WinGuardian.Tray\WinGuardian.Tray.csproj') -c Release -o (Join-Path $InstallDir 'Tray')
if ($LASTEXITCODE -ne 0) { throw 'Tray publish failed.' }

if (-not $existing) {
    Write-Host 'Registering service...'
    New-Service -Name $serviceName -BinaryPathName "`"$serviceExe`"" -DisplayName 'WinGuardian Monitor' `
        -Description 'Baselines Windows files, processes and services, and alerts on changes.' `
        -StartupType Automatic | Out-Null
}
# Restart after 5s, 10s, then 60s if the service crashes; reset the failure count daily.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null
# Also apply the restart actions when the service stops with an error code (not only on crashes).
sc.exe failureflag $serviceName 1 | Out-Null

Write-Host 'Starting service...'
Start-Service -Name $serviceName

Write-Host 'Registering tray icon to start at logon...'
Set-ItemProperty -Path $runKey -Name 'WinGuardianTray' -Value "`"$trayExe`""

# Launch through Explorer so the tray runs un-elevated in the user's session, like it will at logon.
Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$trayExe`""

Write-Host ''
Write-Host "WinGuardian installed to $InstallDir" -ForegroundColor Green
if ($existing) {
    Write-Host 'Upgraded in place; the existing baseline, trust list and quarantine were kept.'
} else {
    Write-Host 'The first launch builds the baseline (a full scan of C:\Windows); this can take a while.'
    Write-Host 'Progress is shown in the tray icon tooltip and dashboard.'
}
Write-Host 'Add your free MalwareBazaar / VirusTotal API keys via the tray icon: right-click > Settings...'
