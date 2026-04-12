# pmacs-vpn disconnect script
# Run this as Administrator to disconnect from PMACS VPN

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe from the stable install first, then fall back to local build output.
. "$PSScriptRoot\windows-install.ps1"
$ProjectDir = Get-PmacsProjectRoot -ScriptPath $PSCommandPath
$ExePath = Resolve-PmacsExePath -ProjectRoot $ProjectDir

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
    Write-Host "Install it first:" -ForegroundColor Yellow
    Write-Host "  cd $ProjectDir" -ForegroundColor Cyan
    Write-Host "  .\scripts\windows-install.ps1" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Set working directory to project root (where pmacs-vpn.toml lives)
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
