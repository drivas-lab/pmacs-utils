# pmacs-vpn

Native GlobalProtect VPN client with split-tunneling for PMACS cluster access.

## Why?

The official GlobalProtect client routes *all* your traffic through the VPN (full-tunnel), which:
- Slows down your internet
- Routes personal traffic through institutional servers
- Requires installing bloated client software

This tool only routes PMACS traffic through the VPN, leaving everything else alone.

## Features

- **Split-tunnel** — only PMACS traffic goes through VPN
- **Single binary** — no OpenConnect, no Python, no Java
- **Credential caching** — password stored in OS keychain

## Quick Start (Windows)

```powershell
# First time: save password
pmacs-vpn connect --save-password
# Enter password, approve DUO push

# Future connects: just approve DUO
pmacs-vpn connect

# In another terminal
ssh prometheus.pmacs.upenn.edu

# Disconnect (or Ctrl+C in the VPN window)
pmacs-vpn disconnect
```

Requires **Administrator** privileges.

## Quick Start (macOS / Linux)

```bash
# Connect (requires sudo)
sudo pmacs-vpn connect --save-password

# Disconnect
sudo pmacs-vpn disconnect
```

> macOS and Linux are implemented but not yet tested.

## Configuration

Create `pmacs-vpn.toml`:

```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
username = "your-username"

hosts = [
    "prometheus.pmacs.upenn.edu",
]
```

Or generate a default: `pmacs-vpn init`

## Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect to VPN |
| `disconnect` | Disconnect and clean up |
| `status` | Show connection status |
| `init` | Generate default config |
| `tray` | Run with system tray icon (GUI mode) |

### Connect Options

| Option | Description |
|--------|-------------|
| `--save-password` | Store password in OS keychain |
| `--forget-password` | Clear stored password |
| `-u, --user <USER>` | Override username |
| `--keep-alive` | Aggressive keepalive to prevent idle timeout |
| `--daemon` | Run VPN in background (frees terminal) |

## Daemon Mode

Run VPN in background without keeping a terminal open:

```powershell
# Start VPN daemon
pmacs-vpn connect --daemon

# Check if running
pmacs-vpn status

# Stop
pmacs-vpn disconnect
```

## System Tray Mode

Run with a system tray icon for GUI-based control:

```powershell
pmacs-vpn tray
```

Right-click the tray icon for Connect/Disconnect/Exit options.

## Desktop Shortcuts (Windows)

Double-click shortcuts are available in `scripts/`:
- `connect.ps1` — Connect with auto-elevation
- `disconnect.ps1` — Disconnect with auto-elevation

See [docs/windows-shortcut.md](docs/windows-shortcut.md) for setup.

## Platform Status

| Platform | Status |
|----------|--------|
| Windows | Working |
| macOS | Needs testing |
| Linux | Needs testing |

## Building

```bash
cargo build --release
```

Binary: `target/release/pmacs-vpn` (`.exe` on Windows)

Windows embeds wintun.dll automatically — no manual setup needed.
