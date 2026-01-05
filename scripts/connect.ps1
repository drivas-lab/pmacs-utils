# pmacs-vpn connect script
# Runs VPN in foreground (keeps terminal open while connected)
# For background operation, use tray.ps1 (requires password to be cached first)

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe relative to this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path (Split-Path -Parent $ScriptDir) "target\release\pmacs-vpn.exe"

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
