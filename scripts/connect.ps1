# pmacs-vpn connect script
# Runs VPN in foreground (keeps terminal open while connected)
# For background operation, use tray.ps1 (requires password to be cached first)

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe from the stable install first, then fall back to local build output.
. "$PSScriptRoot\windows-install.ps1"
$ProjectDir = Get-PmacsProjectRoot -ScriptPath $PSCommandPath
$ExePath = Resolve-PmacsExePath -ProjectRoot $ProjectDir

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
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
Write-Host "  PMACS VPN Connect" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if already connected
$status = & $ExePath status 2>&1
if ($status -match "VPN Status: Connected") {
    Write-Host "VPN is already connected!" -ForegroundColor Green
    Write-Host ""
    $status | ForEach-Object { Write-Host $_ }
    Write-Host ""
    Write-Host "To disconnect: pmacs-vpn disconnect" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 0
}

Write-Host "Starting VPN connection..." -ForegroundColor Green
Write-Host ""
Write-Host "  1. Enter your password when prompted" -ForegroundColor White
Write-Host "  2. Approve the DUO push on your phone" -ForegroundColor White
Write-Host "  3. Keep this window open while connected" -ForegroundColor White
Write-Host "  4. Press Ctrl+C to disconnect" -ForegroundColor White
Write-Host ""
Write-Host "Tip: Add --save-password to cache your password for next time" -ForegroundColor DarkGray
Write-Host ""

try {
    & $ExePath connect
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Host ""
        Write-Host "VPN disconnected cleanly." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "VPN exited with code: $exitCode" -ForegroundColor Yellow
    }
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to close"
