# Create desktop shortcuts for PMACS VPN
$desktop = [Environment]::GetFolderPath('Desktop')
$scriptDir = 'C:\drivaslab\pmacs-utils\scripts'

$ws = New-Object -ComObject WScript.Shell

# PMACS VPN Tray
$shortcut = $ws.CreateShortcut("$desktop\PMACS VPN Tray.lnk")
$shortcut.TargetPath = 'powershell.exe'
$shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$scriptDir\tray.ps1`""
$shortcut.WorkingDirectory = 'C:\drivaslab\pmacs-utils'
$shortcut.IconLocation = 'shell32.dll,13'
$shortcut.Save()
Write-Host "Created: PMACS VPN Tray.lnk"

# PMACS VPN Connect
$shortcut = $ws.CreateShortcut("$desktop\PMACS VPN Connect.lnk")
$shortcut.TargetPath = 'powershell.exe'
$shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$scriptDir\connect.ps1`""
$shortcut.WorkingDirectory = 'C:\drivaslab\pmacs-utils'
$shortcut.IconLocation = 'shell32.dll,13'
$shortcut.Save()
Write-Host "Created: PMACS VPN Connect.lnk"

# PMACS VPN Disconnect
$shortcut = $ws.CreateShortcut("$desktop\PMACS VPN Disconnect.lnk")
$shortcut.TargetPath = 'powershell.exe'
$shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$scriptDir\disconnect.ps1`""
$shortcut.WorkingDirectory = 'C:\drivaslab\pmacs-utils'
$shortcut.IconLocation = 'shell32.dll,14'
$shortcut.Save()
Write-Host "Created: PMACS VPN Disconnect.lnk"

Write-Host ""
Write-Host "Desktop shortcuts created!"
