# pmacs-vpn system tray
# Double-click this shortcut to run VPN in system tray

$ErrorActionPreference = "Stop"

# Find pmacs-vpn.exe from the stable install first, then fall back to local build output.
. "$PSScriptRoot\windows-install.ps1"
$ProjectDir = Get-PmacsProjectRoot -ScriptPath $PSCommandPath
$ExePath = Resolve-PmacsExePath -ProjectRoot $ProjectDir

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
        "pmacs-vpn.exe not found at:`n$ExePath`n`nInstall it first:`n  cd $ProjectDir`n  .\scripts\windows-install.ps1",
        "PMACS VPN Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# Set working directory to project root (where pmacs-vpn.toml lives)
Set-Location $ProjectDir

# Start tray mode (this runs until user exits via tray menu)
& $ExePath tray
