#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the WinGuardian service, tray autostart and program files.
    The baseline/event database in C:\ProgramData\WinGuardian is kept unless -RemoveData is given.
#>
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WinGuardian'),
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'WinGuardian'

Get-Process -Name 'WinGuardian.Tray' -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'WinGuardianTray' -ErrorAction SilentlyContinue

# Explorer right-click menu entries (see install.ps1).
$classes = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Classes', $true)
try {
    $classes.DeleteSubKeyTree('*\shell\WinGuardian.Scan', $false)
    foreach ($ext in '.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.msi', '.hta') {
        $classes.DeleteSubKeyTree("SystemFileAssociations\$ext\shell\WinGuardian.Run", $false)
    }
} finally { $classes.Close() }

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
}

if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
Remove-Item -Path 'HKLM:\SOFTWARE\WinGuardian' -Recurse -Force -ErrorAction SilentlyContinue

if ($RemoveData) {
    $data = Join-Path $env:ProgramData 'WinGuardian'
    if (Test-Path $data) { Remove-Item -Path $data -Recurse -Force }
    Write-Host 'Baseline database removed.'
}

Write-Host 'WinGuardian uninstalled.' -ForegroundColor Green
