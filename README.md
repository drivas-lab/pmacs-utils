# pmacs-vpn

Native GlobalProtect VPN client with split-tunneling for PMACS cluster access.

## Why?

The official GlobalProtect client routes *all* traffic through the VPN, which:
- Slows down your internet
- Blocks access to Gmail and other services
- Sends all your traffic through institutional servers

This tool only routes PMACS traffic through VPN, leaving everything else alone.

## Platform Status

| Platform | CLI | System Tray |
|----------|-----|-------------|
| Windows | ✅ Working | ✅ Working |
| macOS | ✅ Working | ⚠️ In Development |
| Linux | Untested | Untested |

---

## Quick Start (macOS)

### Step 1: Download

Download the binary for your Mac:
- **Apple Silicon (M1/M2/M3):** `pmacs-vpn-aarch64-apple-darwin`
- **Intel Mac:** `pmacs-vpn-x86_64-apple-darwin`

From: [GitHub Releases](../../releases)

### Step 2: Install

Open Terminal and run:

```bash
# Go to your Downloads folder
cd ~/Downloads

# Make it executable
chmod +x pmacs-vpn-*

# Move to a system location (enter your Mac password when prompted)
sudo mv pmacs-vpn-* /usr/local/bin/pmacs-vpn
```

### Step 3: First-Time Setup

```bash
# Create config and save your password
sudo pmacs-vpn connect --save-password
```

**What happens:**
1. Creates `pmacs-vpn.toml` config file
2. Prompts for your **PMACS password** (type it, press Enter)
3. Prompts for **keychain access** (click "Always Allow" to avoid future prompts)
4. Sends a **DUO push** to your phone — approve it
5. Shows "Tunnel running" when connected

**⚠️ Keep this terminal window open!** The VPN runs in the foreground.

### Step 4: Test the Connection

Open a **new terminal window** and try:

```bash
ssh prometheus.pmacs.upenn.edu
```

If SSH connects, you're done! 🎉

### Step 5: Disconnect

Go back to the VPN terminal and press `Ctrl+C`.

---

## Daily Use (macOS)

Once set up, connecting is simple:

```bash
sudo pmacs-vpn connect
```

- No password prompt (uses saved keychain password)
- Just approve the DUO push on your phone
- Keep terminal open while working
- `Ctrl+C` to disconnect

### Background Mode

Don't want to keep a terminal open? Use daemon mode:

```bash
# Start VPN in background
sudo pmacs-vpn connect --daemon

# Check if connected (from any terminal)
pmacs-vpn status

# Disconnect when done
sudo pmacs-vpn disconnect
```

---

## Quick Start (Windows)

### Step 1: Download

Download `pmacs-vpn-x86_64-pc-windows-msvc.exe` from [GitHub Releases](../../releases).

### Step 2: First-Time Setup

Open **Command Prompt as Administrator** and run:

```cmd
cd Downloads
pmacs-vpn-x86_64-pc-windows-msvc.exe connect --save-password
```

Follow the prompts (password, DUO push).

### Step 3: System Tray (Recommended)

After first-time setup, use the system tray for daily use:

```cmd
pmacs-vpn tray
```

- Auto-connects using cached password
- Toast notifications for DUO and connection status
- Right-click tray icon for Connect/Disconnect/Exit
- Enable "Start with Windows" in the menu

---

## Configuration

The config file `pmacs-vpn.toml` is created on first run:

```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
username = "your-pennkey"

hosts = [
    "prometheus.pmacs.upenn.edu",
]
```

**Add more hosts** if you need to access other PMACS servers:

```toml
hosts = [
    "prometheus.pmacs.upenn.edu",
    "consign.pmacs.upenn.edu",
    "some-other-server.pmacs.upenn.edu",
]
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `connect` | Connect to VPN |
| `connect --save-password` | Connect and save password to keychain |
| `connect --daemon` | Connect in background (frees terminal) |
| `disconnect` | Disconnect and clean up routes |
| `status` | Show connection status |
| `init` | Generate default config file |
| `tray` | System tray mode (Windows only for now) |

---

## Troubleshooting

### "Permission denied" or "Operation not permitted"

You need to run with `sudo` on macOS:
```bash
sudo pmacs-vpn connect
```

### Password prompt appears every time

Run with `--save-password` once:
```bash
sudo pmacs-vpn connect --save-password
```

### Keychain keeps asking for permission (macOS)

Click "Always Allow" when the keychain dialog appears. If you clicked "Deny", you may need to:
1. Open Keychain Access
2. Find "pmacs-vpn" entries
3. Delete them
4. Run `--save-password` again

### DUO push not received

- Make sure your phone is unlocked
- Check Duo Mobile app is installed and configured
- Try `--duo-method=call` for a phone call instead

### SSH works but other tools don't

Add the server to your config file's `hosts` list.

### Connection drops after ~16 hours

This is normal — GlobalProtect sessions expire. Just reconnect.

### "Tunnel device not found" or TUN errors

On macOS, you may need to allow the system extension. Check System Preferences → Security & Privacy.

---

## Building from Source

```bash
git clone https://github.com/psom/pmacs-vpn
cd pmacs-vpn
cargo build --release
# Binary at: target/release/pmacs-vpn
```

Requirements: Rust 1.70+

---

## How It Works

1. Authenticates with GlobalProtect using your credentials + DUO
2. Establishes an SSL tunnel to the VPN gateway
3. Creates a virtual network interface (TUN device)
4. Routes only PMACS traffic through the tunnel
5. All other traffic goes through your normal internet connection

Unlike the official client, this never touches your non-PMACS traffic.
