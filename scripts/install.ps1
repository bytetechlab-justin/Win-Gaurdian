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
$displayName = 'WinGaurdian Monitor'
$description = 'WinGaurdian: baselines Windows files, processes, services, scheduled tasks and network activity, and alerts on changes.'

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
    New-Service -Name $serviceName -BinaryPathName "`"$serviceExe`"" -DisplayName $displayName `
        -Description $description -StartupType Automatic | Out-Null
}
# Keep the name shown in Services / Task Manager current (also on upgrades).
sc.exe config $serviceName DisplayName= $displayName | Out-Null
sc.exe description $serviceName $description | Out-Null
# Restart after 5s, 10s, then 60s if the service crashes; reset the failure count daily.
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null
# Also apply the restart actions when the service stops with an error code (not only on crashes).
sc.exe failureflag $serviceName 1 | Out-Null

Write-Host 'Starting service...'
Start-Service -Name $serviceName

Write-Host 'Registering tray icon to start at logon...'
Set-ItemProperty -Path $runKey -Name 'WinGuardianTray' -Value "`"$trayExe`""

# Windows caches each program's display name (shown as the notification sender) in MuiCache.
# Drop the cached entries for the tray so the new name is picked up instead of "WinGuardian.Tray".
$sids = @(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)
$console = (Get-CimInstance Win32_ComputerSystem).UserName
if ($console) { try { $sids += (New-Object System.Security.Principal.NTAccount $console).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {} }
foreach ($sid in ($sids | Select-Object -Unique)) {
    $mui = "Registry::HKEY_USERS\${sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $mui) {
        (Get-Item $mui).Property | Where-Object { $_ -like '*WinGuardian.Tray.exe*' } |
            ForEach-Object { Remove-ItemProperty -Path $mui -Name $_ -ErrorAction SilentlyContinue }
    }
}

# Launch through Explorer so the tray runs un-elevated in the user's session, like it will at logon.
Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$trayExe`""

Write-Host ''
Write-Host "WinGaurdian installed to $InstallDir" -ForegroundColor Green
if ($existing) {
    Write-Host 'Upgraded in place; the existing baseline, trust list and quarantine were kept.'
} else {
    Write-Host 'The first launch builds the baseline (a full scan of C:\Windows); this can take a while.'
    Write-Host 'Progress is shown in the tray icon tooltip and dashboard.'
}
Write-Host 'API keys, auditing and other options: right-click the tray icon > Settings...'
