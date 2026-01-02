<#
.SYNOPSIS
    Connect to PMACS VPN via Docker container

.DESCRIPTION
    Starts the OpenConnect VPN container and waits for the proxy to be ready.
    You'll need to approve a DUO push on your phone.

.PARAMETER Logs
    Attach to container logs after starting (to see DUO prompt)

.EXAMPLE
    .\connect.ps1
    .\connect.ps1 -Logs
#>

param(
    [switch]$Logs
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ProjectDir) { $ProjectDir = Split-Path -Parent $PSScriptRoot }

function Write-Info  { param($Msg) Write-Host "[INFO] $Msg" -ForegroundColor Blue }
function Write-Ok    { param($Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Err "Docker is not installed or not in PATH"
        Write-Info "Install Docker Desktop: https://docker.com/products/docker-desktop"
        exit 1
    }

    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker daemon is not running"
        Write-Info "Start Docker Desktop and try again"
        exit 1
    }
}

function Test-EnvFile {
    $envPath = Join-Path $ProjectDir ".env"
    if (-not (Test-Path $envPath)) {
        Write-Err ".env file not found"
        Write-Info "Copy .env.example to .env and fill in your credentials:"
        Write-Info "  copy .env.example .env"
        exit 1
    }
}

function Test-AlreadyRunning {
    $running = docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'pmacs-vpn' }
    if ($running) {
        Write-Warn "VPN container is already running"
        Write-Info "Use '.\disconnect.ps1' to stop, or '.\status.ps1' to check status"
        exit 0
    }
}

function Start-VPN {
    Write-Info "Starting PMACS VPN container..."

    Push-Location $ProjectDir
    try {
        docker compose up -d
    } finally {
        Pop-Location
    }

    Write-Ok "Container started"
    Write-Host ""
    Write-Host ">>> CHECK YOUR PHONE FOR DUO PUSH <<<" -ForegroundColor Cyan
    Write-Host ""
}

function Wait-ForProxy {
    Write-Info "Waiting for VPN tunnel and proxy..."

    $maxAttempts = 30
    $attempt = 0

    while ($attempt -lt $maxAttempts) {
        $tcpTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 8889 -WarningAction SilentlyContinue
        if ($tcpTest.TcpTestSucceeded) {
            Write-Ok "SOCKS5 proxy is ready on localhost:8889"
            Write-Ok "HTTP proxy is ready on localhost:8888"
            return $true
        }

        $attempt++
        Start-Sleep -Seconds 2
    }

    Write-Err "Proxy did not become ready within 60 seconds"
    Write-Info "Check logs with: docker logs pmacs-vpn"
    return $false
}

# Main
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  PMACS VPN Connect" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Test-Docker
Test-EnvFile
Test-AlreadyRunning
Start-VPN

if ($Logs) {
    Write-Info "Attaching to logs (Ctrl+C to detach)..."
    docker logs -f pmacs-vpn
} else {
    if (Wait-ForProxy) {
        Write-Host ""
        Write-Ok "VPN connected! You can now SSH to PMACS hosts."
        Write-Info "Example: ssh prometheus"
        Write-Host ""
        Write-Info "To see VPN logs: docker logs pmacs-vpn"
        Write-Info "To disconnect:   .\scripts\disconnect.ps1"
    }
}
