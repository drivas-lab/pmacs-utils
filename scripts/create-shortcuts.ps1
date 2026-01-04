# Create shortcuts for PMACS VPN
# Direct exe shortcuts (no PowerShell wrapper - more reliable)
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = [Environment]::GetFolderPath('StartMenu')
$exePath = 'C:\drivaslab\pmacs-utils\target\release\pmacs-vpn.exe'
$workDir = 'C:\drivaslab\pmacs-utils'

$ws = New-Object -ComObject WScript.Shell

# Helper to set "Run as administrator" flag on a shortcut
function Set-RunAsAdmin($lnkPath) {
    $bytes = [System.IO.File]::ReadAllBytes($lnkPath)
    $bytes[21] = $bytes[21] -bor 0x20
    [System.IO.File]::WriteAllBytes($lnkPath, $bytes)
}

# PMACS VPN Connect
$lnkPath = "$desktop\PMACS VPN Connect.lnk"
$shortcut = $ws.CreateShortcut($lnkPath)
$shortcut.TargetPath = $exePath
$shortcut.Arguments = 'connect'
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = 'shell32.dll,13'
$shortcut.Save()
Set-RunAsAdmin $lnkPath
Write-Host "Created: PMACS VPN Connect.lnk"

# PMACS VPN Tray
$lnkPath = "$desktop\PMACS VPN Tray.lnk"
$shortcut = $ws.CreateShortcut($lnkPath)
$shortcut.TargetPath = $exePath
$shortcut.Arguments = 'tray'
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = 'shell32.dll,13'
$shortcut.Save()
Set-RunAsAdmin $lnkPath
Write-Host "Created: PMACS VPN Tray.lnk"

# PMACS VPN Disconnect
$lnkPath = "$desktop\PMACS VPN Disconnect.lnk"
$shortcut = $ws.CreateShortcut($lnkPath)
$shortcut.TargetPath = $exePath
$shortcut.Arguments = 'disconnect'
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = 'shell32.dll,14'
$shortcut.Save()
Set-RunAsAdmin $lnkPath
Write-Host "Created: PMACS VPN Disconnect.lnk"

# Start Menu - PMACS VPN Tray only
$lnkPath = "$startMenu\PMACS VPN Tray.lnk"
$shortcut = $ws.CreateShortcut($lnkPath)
$shortcut.TargetPath = $exePath
$shortcut.Arguments = 'tray'
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = 'shell32.dll,13'
$shortcut.Save()
Set-RunAsAdmin $lnkPath
Write-Host "Created: Start Menu\PMACS VPN Tray.lnk"

Write-Host ""
Write-Host "Shortcuts created (direct exe, Run as Administrator):"
Write-Host "  Desktop: Connect, Tray, Disconnect"
Write-Host "  Start Menu: Tray"
