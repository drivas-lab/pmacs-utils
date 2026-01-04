# Windows Shortcuts

Desktop and Start Menu shortcuts for one-click VPN access.

## Prerequisites

1. Build the release binary:
   ```powershell
   cd C:\drivaslab\pmacs-utils
   cargo build --release
   ```

2. First-time setup (cache your password):
   ```powershell
   .\target\release\pmacs-vpn.exe connect --save-password
   ```

## Create Shortcuts

Run the shortcut creation script:

```powershell
cd C:\drivaslab\pmacs-utils
.\scripts\create-shortcuts.ps1
```

This creates:
- **Desktop:** PMACS VPN Connect, PMACS VPN Tray, PMACS VPN Disconnect
- **Start Menu:** PMACS VPN Tray

All shortcuts are configured to "Run as Administrator" automatically.

## Recommended: Tray Mode

The **PMACS VPN Tray** shortcut is the best way to use the VPN:

1. Double-click the shortcut (Desktop or Start Menu)
2. Approve UAC prompt
3. VPN auto-connects if password is cached
4. Approve DUO push on your phone
5. Icon appears in system tray (green = connected)

Right-click tray icon for menu: Connect, Disconnect, Start with Windows, Exit.

## Start with Windows

From the tray menu, enable "Start with Windows" to auto-launch on login. This adds a registry entry visible in Task Manager → Startup Apps.

## VS Code Remote SSH

Once connected, SSH to prometheus from VS Code:

### First-Time Setup

1. Install the **Remote - SSH** extension
2. Open Command Palette (Ctrl+Shift+P) → `Remote-SSH: Open SSH Configuration File`
3. Add:
   ```
   Host prometheus
       HostName prometheus.pmacs.upenn.edu
       User your-username
       ServerAliveInterval 60
   ```

### Connecting

1. Connect to VPN (tray icon should be green)
2. Click green remote icon in VS Code bottom-left
3. Select **Connect to Host...** → **prometheus**
4. Enter password when prompted

## Troubleshooting

### "pmacs-vpn.exe not found"
Build the release binary first:
```powershell
cargo build --release
```

### UAC prompt doesn't appear / Access denied
Right-click shortcut → Properties → Advanced → check "Run as administrator"

### DUO push not arriving
- Check phone has internet
- Ensure DUO Mobile app is installed and configured
- Try `sms` or `phone` method if push fails

### Can't resolve prometheus.pmacs.upenn.edu
VPN might not be fully connected. Check tray icon is green, or run `pmacs-vpn status`.
