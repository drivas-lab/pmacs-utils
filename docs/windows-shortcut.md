# Windows Shortcut Setup

Quick desktop shortcut for one-click VPN connection.

## Prerequisites

1. Build the release binary:
   ```powershell
   cd C:\drivaslab\pmacs-utils
   cargo build --release
   ```

2. Create config file `pmacs-vpn.toml` in project root:
   ```toml
   [vpn]
   gateway = "psomvpn.uphs.upenn.edu"
   username = "your-username"

   hosts = [
       "prometheus.pmacs.upenn.edu",
   ]
   ```

## Create Desktop Shortcut

1. Right-click on Desktop, select **New > Shortcut**

2. Enter this target:
   ```
   powershell.exe -ExecutionPolicy Bypass -File "C:\drivaslab\pmacs-utils\scripts\connect.ps1"
   ```

3. Name it: `PMACS VPN`

4. Right-click the new shortcut, select **Properties**

5. Click **Advanced...**, check **Run as administrator**

6. Click **OK** twice

### Optional: Custom Icon

In Properties > Shortcut tab > Change Icon, browse to an `.ico` file of your choice.

## Usage

1. Double-click the shortcut
2. Approve the Windows UAC prompt (admin access required for VPN)
3. Enter your PMACS password
4. Approve the DUO push on your phone
5. Wait for "Connected" message
6. Leave the window open while using VPN
7. Press Ctrl+C or close window to disconnect

## VS Code Remote SSH

Once connected, you can SSH to prometheus from VS Code:

### First-Time Setup

1. Install the **Remote - SSH** extension in VS Code

2. Open Command Palette (Ctrl+Shift+P), run: `Remote-SSH: Open SSH Configuration File`

3. Add this entry:
   ```
   Host prometheus
       HostName prometheus.pmacs.upenn.edu
       User your-username
       ServerAliveInterval 60
   ```

4. Save the file

### Connecting

1. Connect to PMACS VPN (double-click shortcut)
2. In VS Code, click the green remote icon in bottom-left corner
3. Select **Connect to Host...**
4. Choose **prometheus**
5. Enter password when prompted
6. VS Code opens a remote window to prometheus

### Tips

- Keep the VPN window open while using VS Code Remote
- If connection drops, reconnect VPN first, then reopen VS Code remote
- Use `ServerAliveInterval 60` in SSH config to prevent timeouts

## Troubleshooting

### "pmacs-vpn.exe not found"

Build the release binary:
```powershell
cd C:\drivaslab\pmacs-utils
cargo build --release
```

### "Access denied" or VPN fails

Make sure the shortcut is set to **Run as administrator**.

### DUO push not arriving

- Check your phone has internet
- Try `sms` or `phone` instead of approving push
- Contact PMACS IT if DUO is not configured

### Can't resolve prometheus.pmacs.upenn.edu

VPN might not be fully connected. Check the VPN window shows "Connected" status.
