# pmacs-vpn

Split-tunnel VPN utility for PMACS.

The official GlobalProtect VPN routes all of your traffic through PMACS.
This slows down everything, blocks access to Gmail, and is generally creepy.

This is a lightweight alternative that keeps your non-PMACS traffic private.
Written in Rust and pure spite.

# Quickstart (Local Dev)

## Quality Gate

Run the local anti-drift gate before pushing:

```bash
./scripts/quality-gate.sh
```

Fast variant:

```bash
./scripts/quality-gate.sh --quick
```

See `QUALITY.md` for expected behavior invariants and review standards.

## macOS (menu-bar tray)

```bash
# Build locally
cargo build

# One-time setup + save credentials
./target/debug/pmacs-vpn init
sudo ./target/debug/pmacs-vpn connect --save-password
sudo ./target/debug/pmacs-vpn disconnect

# Start tray in menu bar (run as normal user, not sudo)
./target/debug/pmacs-vpn tray
```

Tray behavior on macOS:
- Connect/Reconnect/Disconnect now work from the tray like Windows.
- First connect (or after binary path changes) may show a macOS admin prompt to install/update the privileged LaunchDaemon.
- After that one-time setup, normal tray connect/reconnect should not prompt each time.
- Login auto-start opens tray only; it does not auto-connect (avoids repeated password prompts at login).
- Use tray menu `macOS Permissions` to view Accessibility/Input Monitoring diagnostics.

### Optional: Touch ID for sudo (better UX for non-tray CLI flows)

```bash
sudo sed -i '' '2i\
auth       sufficient     pam_tid.so
' /etc/pam.d/sudo
```

## Windows (system tray)

Run from an Administrator terminal:

```powershell
cargo build
.\target\debug\pmacs-vpn.exe init
.\target\debug\pmacs-vpn.exe connect --save-password
.\target\debug\pmacs-vpn.exe disconnect
.\target\debug\pmacs-vpn.exe tray
```

Tray behavior on Windows:
- `tray` relaunches itself hidden (no console window).
- Connect/Reconnect/Disconnect work from tray.
- `Start with Windows` menu option controls auto-start registry entry.
- Login auto-start opens tray only; it does not auto-connect.

## Background CLI mode (both platforms)

```bash
sudo ./target/debug/pmacs-vpn connect --background
./target/debug/pmacs-vpn status
sudo ./target/debug/pmacs-vpn disconnect
```

## Tray Architecture (Current)

- `src/tray.rs`: UI/event-loop layer only (menu, icon, state rendering).
- `src/main.rs`: cross-platform tray controller (command handling, daemon lifecycle, health monitor, reconnect logic).
- `src/ipc/*`: tray-daemon protocol (ping/status/disconnect) over named pipe (Windows) or Unix socket (macOS/Linux).
- `src/macos_permissions.rs`: macOS diagnostics for Accessibility and Input Monitoring checks.

## Platform Parity Notes

- Windows and macOS now share the same tray command/state controller path.
- Both platforms expose Connect, Disconnect, Reconnect, Start-at-login, DUO method, and saved-password toggles.
- macOS difference: tray connect/reconnect performs admin elevation via macOS prompt instead of requiring tray to run as root.

---

## Why not just use GlobalProtect?

| | pmacs-vpn | GlobalProtect |
|---|-----------|---------------|
| **Memory (connected)** | 12 MB | 230 MB |
| **Memory (idle)** | 0 MB | 73 MB |
| **Install size** | 5 MB | 162 MB |
| **Background processes** | None | 2-3 (always) |
| **Blocks Gmail** | No | Yes |
| **Watches all your traffic** | No | Yes |

GlobalProtect runs three background processes 24/7 eating 73 MB of RAM even when you're not using it.
When connected, it balloons to 230 MB and routes *everything* through Penn Medicine's network; your
email, your Spotify, your Google searches. All of it.

pmacs-vpn connects only when you need it, routes only PMACS hosts through the tunnel, and exits
cleanly when you're done. Your other traffic stays between you and your ISP.


## Configuration

Settings are stored in `pmacs-vpn.toml` (created by `pmacs-vpn init`).

```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"
username = "your_pennkey"  # optional, prompts if not set

hosts = ["prometheus.pmacs.upenn.edu"]  # hosts to route through VPN

[preferences]
save_password = true          # store password in OS keychain
duo_method = "push"           # push, sms, call, or passcode
start_at_login = false        # start tray at OS login
auto_connect = true           # auto-connect on manual tray launch (not on login auto-start)
auto_reconnect = true         # reconnect if VPN drops unexpectedly
max_reconnect_attempts = 3    # give up after N failed reconnects
reconnect_delay_secs = 5      # base delay between reconnect attempts
inbound_timeout_secs = 45     # detect dead tunnels (lower = faster detection)
```

### Tunnel health

The VPN detects dead connections by monitoring inbound traffic. If no data arrives within `inbound_timeout_secs`, the tunnel is considered dead and will auto-reconnect (if enabled).

- **Default:** 45 seconds
- **Lower values:** Faster detection, but may cause false positives on slow connections
- **Tray mode:** Uses aggressive keepalive (10s) for faster detection
