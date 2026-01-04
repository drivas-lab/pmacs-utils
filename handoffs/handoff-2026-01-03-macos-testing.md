# Handoff: macOS Testing

**Date:** 2026-01-03
**From:** Windows implementation complete
**To:** macOS testing and fixes

---

## Project Overview

**pmacs-vpn** is a native GlobalProtect VPN client with split-tunneling for PMACS cluster access. It routes only specified hosts through VPN, leaving other traffic alone.

**Key docs:**
- `CLAUDE.md` - Project overview, architecture, current status
- `README.md` - User-facing documentation
- `TODO.md` - Roadmap and remaining work
- `docs/native-gp-implementation-plan.md` - Technical implementation spec
- `docs/testing-guide.md` - Full test procedures

---

## Windows Status: COMPLETE

Everything works on Windows:
- Full auth flow (password + DUO push)
- SSL tunnel with async TUN I/O
- Split-tunnel routing
- Credential caching (Windows Credential Manager)
- Daemon mode, system tray, notifications
- 70 unit tests passing

---

## macOS Testing Checklist

### 1. Build
```bash
cd /path/to/pmacs-utils
cargo build --release
```

Should compile without errors. If dependencies fail, check Cargo.toml.

### 2. Basic CLI Test
```bash
# Generate config
./target/release/pmacs-vpn init

# Check it created pmacs-vpn.toml
cat pmacs-vpn.toml
```

### 3. Connection Test (requires sudo)
```bash
sudo ./target/release/pmacs-vpn -v connect
```

**Expected flow:**
1. Prompts for password
2. Sends DUO push
3. Creates TUN device (utun*)
4. Establishes SSL tunnel
5. Adds routes for prometheus.pmacs.upenn.edu
6. Shows "Connected!"

### 4. Verify Routing (in another terminal)
```bash
# Check route was added
netstat -rn | grep prometheus
# or
netstat -rn | grep 172.16

# Test connectivity
ping prometheus.pmacs.upenn.edu

# Test SSH
ssh prometheus.pmacs.upenn.edu
```

### 5. Disconnect
Press Ctrl+C or run:
```bash
./target/release/pmacs-vpn disconnect
```

Verify routes are cleaned up:
```bash
netstat -rn | grep 172.16  # Should be empty
```

---

## Platform-Specific Code Locations

| Component | File | macOS Notes |
|-----------|------|-------------|
| Routing | `src/platform/mac.rs` | Uses `route -n add -host <ip> -interface <utun>` |
| TUN device | `src/gp/tun.rs` | Uses `tun` crate, creates utun* device |
| Credentials | `src/credentials.rs` | Uses `keyring` crate → macOS Keychain |
| State dir | `src/state.rs:193` | Uses `$HOME/.pmacs-vpn/` |
| Hosts file | `src/vpn/hosts.rs` | Uses `/etc/hosts` |
| Tray | `src/tray.rs` | **Windows-only currently** |
| Notifications | `src/notifications.rs` | **Windows-only currently** |
| Startup | `src/startup.rs` | **Windows-only currently** |

---

## Likely Issues to Fix

### 1. TUN Device Creation
The `tun` crate (0.8) should work on macOS, but may need:
- Permissions (must run as root/sudo)
- Different device naming (utun0, utun1, etc.)

**Debug:**
```bash
sudo ./target/release/pmacs-vpn -v connect
# Look for "TUN device created: utunX"
```

### 2. Route Commands
macOS uses different route syntax. Current implementation in `src/platform/mac.rs`:
```bash
route -n add -host <destination> -interface <utun>
```

If routes fail, check:
```bash
# Manual test
sudo route -n add -host 172.16.38.40 -interface utun0
```

### 3. Keychain Access
The `keyring` crate should use macOS Keychain automatically. If credential storage fails:
```bash
# Test manually
./target/release/pmacs-vpn connect --save-password
# Then check Keychain Access app for "pmacs-vpn" entry
```

### 4. Hosts File Permissions
Writing to `/etc/hosts` requires sudo. The code already handles this, but verify:
```bash
cat /etc/hosts | grep pmacs
```

---

## Architecture Quick Reference

```
src/
├── main.rs          # CLI + connect/disconnect flow
├── config.rs        # TOML config parsing
├── credentials.rs   # OS keychain (cross-platform via keyring crate)
├── state.rs         # Connection state persistence
├── gp/              # GlobalProtect protocol
│   ├── auth.rs      # prelogin → login → getconfig
│   ├── tunnel.rs    # SSL tunnel + async event loop
│   ├── tun.rs       # TUN device wrapper
│   └── packet.rs    # GP packet framing
├── platform/        # OS-specific routing
│   ├── mac.rs       # ← macOS routing
│   ├── linux.rs
│   └── windows.rs
└── vpn/
    ├── routing.rs   # DNS resolution + route management
    └── hosts.rs     # /etc/hosts management
```

---

## Key Dependencies

From Cargo.toml:
- `tun = "0.8"` - Cross-platform TUN device
- `tokio-rustls` - TLS for SSL tunnel
- `keyring` - Cross-platform credential storage
- `clap` - CLI parsing
- `serde` - Config/state serialization
- `tracing` - Logging

---

## Running Tests

```bash
cargo test
cargo clippy
```

70 tests should pass. 2 are ignored (require credential manager access).

---

## What's NOT Implemented for macOS

1. **System tray** - Windows-only (`tray.rs` has `#[cfg(target_os = "windows")]`)
2. **Toast notifications** - Windows-only
3. **"Start with Windows"** - Windows-only (registry-based)

These are nice-to-have for macOS but not required for core functionality.

---

## Config File

`pmacs-vpn.toml` in working directory:
```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
username = "yjk"

hosts = [
    "prometheus.pmacs.upenn.edu",
]
```

---

## Success Criteria

1. [ ] `cargo build --release` succeeds
2. [ ] `pmacs-vpn init` creates config
3. [ ] `sudo pmacs-vpn connect` authenticates (password + DUO)
4. [ ] TUN device created (utun*)
5. [ ] Routes added for configured hosts
6. [ ] `ssh prometheus.pmacs.upenn.edu` works while connected
7. [ ] Ctrl+C disconnects cleanly
8. [ ] Routes and state cleaned up after disconnect

---

## Troubleshooting

### "Permission denied" creating TUN
Must run as root: `sudo ./target/release/pmacs-vpn connect`

### "Failed to add route"
Check route command syntax. May need to adjust `src/platform/mac.rs`.

### DUO push not received
Check phone has internet, DUO app is installed.

### SSH hangs
Check routes exist (`netstat -rn`), check tunnel is passing traffic (look for "TUN read X bytes" in verbose output).

---

## Contact

If stuck, check:
1. `docs/auth-flow-investigation.md` - Debugging notes from Windows implementation
2. `docs/testing-guide.md` - Comprehensive test procedures
3. Run with `-v` flag for verbose logging
4. Run with `RUST_LOG=debug` for maximum detail:
   ```bash
   RUST_LOG=debug sudo ./target/release/pmacs-vpn -v connect
   ```
