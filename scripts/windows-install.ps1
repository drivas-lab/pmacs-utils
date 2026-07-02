param(
    [switch]$SkipBuild
)

function Get-PmacsProjectRoot {
    param(
        [string]$ScriptPath = $PSCommandPath
    )

    $scriptDir = Split-Path -Parent $ScriptPath
    return Split-Path -Parent $scriptDir
}

function Get-PmacsStableInstallDir {
    param(
        [string]$LocalAppData = $env:LOCALAPPDATA
    )

    if (-not $LocalAppData) {
        throw "LOCALAPPDATA is not set."
    }

    return Join-Path $LocalAppData "Programs\PMACS VPN"
}

function Get-PmacsStableExePath {
    param(
        [string]$LocalAppData = $env:LOCALAPPDATA
    )

    return Join-Path (Get-PmacsStableInstallDir -LocalAppData $LocalAppData) "pmacs-vpn.exe"
}

function Get-PmacsBuildExePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot
    )

    return Join-Path $ProjectRoot "target\release\pmacs-vpn.exe"
}

function Resolve-PmacsExePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot,
        [string]$LocalAppData = $env:LOCALAPPDATA,
        [Nullable[bool]]$StableExists = $null,
        [Nullable[bool]]$BuildExists = $null
    )

    $stableExe = Get-PmacsStableExePath -LocalAppData $LocalAppData
    $buildExe = Get-PmacsBuildExePath -ProjectRoot $ProjectRoot

    if ($null -eq $StableExists) {
        $StableExists = Test-Path $stableExe
    }

    if ($null -eq $BuildExists) {
        $BuildExists = Test-Path $buildExe
    }

    if ($StableExists) {
        return $stableExe
    }

    if ($BuildExists) {
        return $buildExe
    }

    return $stableExe
}

function Install-PmacsBinary {
    param(
        [string]$ProjectRoot = (Get-PmacsProjectRoot),
        [string]$LocalAppData = $env:LOCALAPPDATA,
        [switch]$SkipBuild
    )

    $buildExe = Get-PmacsBuildExePath -ProjectRoot $ProjectRoot
    $stableDir = Get-PmacsStableInstallDir -LocalAppData $LocalAppData
    $stableExe = Get-PmacsStableExePath -LocalAppData $LocalAppData

    if (-not (Test-Path $buildExe)) {
        if ($SkipBuild) {
            throw "Release binary not found at $buildExe"
        }

        Write-Host "Building release binary..." -ForegroundColor Cyan
        Push-Location $ProjectRoot
        try {
            & cargo build --release
            if ($LASTEXITCODE -ne 0) {
                throw "cargo build --release failed with exit code $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
    }

    New-Item -ItemType Directory -Path $stableDir -Force | Out-Null
    Copy-Item $buildExe $stableExe -Force

    Write-Host "Installed pmacs-vpn to $stableExe" -ForegroundColor Green
    return $stableExe
}

if ($MyInvocation.InvocationName -ne '.') {
    Install-PmacsBinary -SkipBuild:$SkipBuild
}
