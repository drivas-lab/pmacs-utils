# pmacs-vpn system tray
# Double-click this shortcut to run VPN in system tray

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe relative to this script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path (Split-Path -Parent $ScriptDir) "target\release\pmacs-vpn.exe"

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Relaunch as admin with hidden window (tray runs in background)
    Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Check if exe exists
if (-not (Test-Path $ExePath)) {
    # Show error in message box since we're running hidden
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "pmacs-vpn.exe not found at:`n$ExePath`n`nBuild it first:`n  cd C:\drivaslab\pmacs-utils`n  cargo build --release",
        "PMACS VPN Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# Set working directory to project root (where pmacs-vpn.toml lives)
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

# Start tray mode (this runs until user exits via tray menu)
& $ExePath tray
