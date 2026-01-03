# pmacs-vpn disconnect script
# Run this as Administrator to disconnect from PMACS VPN

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe relative to this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path (Split-Path -Parent $ScriptDir) "target\release\pmacs-vpn.exe"

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Check if exe exists
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: pmacs-vpn.exe not found at:" -ForegroundColor Red
    Write-Host "  $ExePath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Build it first:" -ForegroundColor Yellow
    Write-Host "  cd C:\drivaslab\pmacs-utils" -ForegroundColor Cyan
    Write-Host "  cargo build --release" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Set working directory to project root (where pmacs-vpn.toml lives)
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PMACS VPN Disconnect" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    & $ExePath disconnect
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host ""
        Write-Host "VPN disconnected and cleaned up." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Disconnect exited with code: $exitCode" -ForegroundColor Yellow
    }
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to close"
