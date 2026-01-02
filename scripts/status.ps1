<#
.SYNOPSIS
    Check PMACS VPN status
#>

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  PMACS VPN Status" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "Docker:" -ForegroundColor Blue
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "  Not installed" -ForegroundColor Red
    exit 1
}

$null = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Installed but not running" -ForegroundColor Yellow
    exit 1
}
Write-Host "  Running" -ForegroundColor Green
Write-Host ""

# Check container
Write-Host "VPN Container:" -ForegroundColor Blue
$running = docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'pmacs-vpn' }
if (-not $running) {
    Write-Host "  Not running" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To connect: .\scripts\connect.ps1"
    exit 0
}

$status = docker inspect --format '{{.State.Status}}' pmacs-vpn 2>$null
$started = docker inspect --format '{{.State.StartedAt}}' pmacs-vpn 2>$null
Write-Host "  Status: $status" -ForegroundColor Green
Write-Host "  Started: $($started.Split('.')[0])"
Write-Host ""

# Check proxies
Write-Host "Proxy Ports:" -ForegroundColor Blue
$socks = Test-NetConnection -ComputerName 127.0.0.1 -Port 8889 -WarningAction SilentlyContinue
if ($socks.TcpTestSucceeded) {
    Write-Host "  SOCKS5 (8889): listening" -ForegroundColor Green
} else {
    Write-Host "  SOCKS5 (8889): not responding" -ForegroundColor Red
}

$http = Test-NetConnection -ComputerName 127.0.0.1 -Port 8888 -WarningAction SilentlyContinue
if ($http.TcpTestSucceeded) {
    Write-Host "  HTTP   (8888): listening" -ForegroundColor Green
} else {
    Write-Host "  HTTP   (8888): not responding" -ForegroundColor Red
}
Write-Host ""
