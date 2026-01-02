<#
.SYNOPSIS
    Disconnect from PMACS VPN
#>

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ProjectDir) { $ProjectDir = Split-Path -Parent $PSScriptRoot }

function Write-Info { param($Msg) Write-Host "[INFO] $Msg" -ForegroundColor Blue }
function Write-Ok   { param($Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  PMACS VPN Disconnect" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$running = docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'pmacs-vpn' }
if (-not $running) {
    Write-Info "VPN container is not running"
    exit 0
}

Write-Info "Stopping VPN container..."

Push-Location $ProjectDir
try {
    docker compose down
} finally {
    Pop-Location
}

Write-Ok "VPN disconnected"
