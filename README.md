# pmacs-vpn

Native GlobalProtect VPN client with split-tunneling for PMACS cluster access.

## Why?

The official GlobalProtect client routes *all* traffic through the VPN, which slows down your connection and sends personal browsing through institutional servers.

This tool only routes PMACS traffic through VPN, leaving everything else alone.

## Features

- **Split-tunnel** — only PMACS traffic goes through VPN
- **Single binary** — no OpenConnect, no Python, no Java
- **Credential caching** — password stored in OS keychain
- **Background mode** — runs as daemon or system tray

## Platform Status

| Platform | Status |
|----------|--------|
| Windows | **Working** |
| macOS | Untested (help wanted) |
| Linux | Untested (help wanted) |

## Setup

### Prerequisites

1. Build the binary:
   ```bash
   cargo build --release
   ```

2. The binary is at `target/release/pmacs-vpn` (`.exe` on Windows)

### First-Time Setup

```bash
# Run once to set up config and cache password
pmacs-vpn connect --save-password

# Enter your password when prompted
# Approve the DUO push on your phone
# Ctrl+C to disconnect when done
```

This creates `pmacs-vpn.toml` and stores your password in the OS keychain.

### Daily Use

After first-time setup, connecting is simple:

```bash
pmacs-vpn connect
# Just approve DUO - no password needed
```

## Commands

| Command | Description |
|---------|-------------|
| `connect` | Connect to VPN |
| `disconnect` | Disconnect and clean up |
| `status` | Show connection status |
| `init` | Generate default config |
| `tray` | Run with system tray (GUI mode) |

### Connect Options

| Option | Description |
|--------|-------------|
| `--save-password` | Store password in OS keychain |
| `--forget-password` | Clear stored password, prompt fresh |
| `-u, --user <USER>` | Override username |
| `--daemon` | Run in background (frees terminal) |
| `--keep-alive` | Aggressive keepalive (10s vs 30s) |

## Background Mode

Run VPN without keeping a terminal open:

```bash
# Start in background
pmacs-vpn connect --daemon

# Check status anytime
pmacs-vpn status

# Stop
pmacs-vpn disconnect
```

## System Tray (Windows)

For GUI-based control, use the system tray:

```bash
pmacs-vpn tray
```

Right-click the tray icon for Connect/Disconnect/Exit.

**Note:** Tray mode requires password to be cached first. Run `pmacs-vpn connect --save-password` before using the tray.

## Windows Shortcuts

Double-click shortcuts in `scripts/`:
- `tray.ps1` — Launch system tray (auto-elevates)
- `connect.ps1` — Connect with auto-elevation

See [docs/windows-shortcut.md](docs/windows-shortcut.md) for desktop shortcut setup.

## Configuration

The config file `pmacs-vpn.toml` is created automatically on first run, or manually:

```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
username = "your-username"

hosts = [
    "prometheus.pmacs.upenn.edu",
]
```

Add more hosts to route additional servers through VPN.

## Troubleshooting

### "Access denied" / Permission errors
Run as Administrator (Windows) or with `sudo` (macOS/Linux).

### DUO push not received
Check your phone is unlocked and Duo Mobile is installed.

### Connection drops after a while
Use `--keep-alive` for more aggressive keepalives. Sessions expire after 16 hours regardless.

### SSH works but other tools timeout
Add the server hostname to `hosts` in your config file.

## Building

```bash
# Build release binary
cargo build --release

# Run tests
cargo test

# Check code quality
cargo clippy
```

Windows embeds `wintun.dll` automatically — no manual setup needed.
