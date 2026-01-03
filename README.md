# pmacs-vpn

Native GlobalProtect VPN client with split-tunneling for PMACS cluster access.

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

### Connect Options

| Option | Description |
|--------|-------------|
| `--save-password` | Store password in OS keychain |
| `--forget-password` | Clear stored password |
| `-u, --user <USER>` | Override username |

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
