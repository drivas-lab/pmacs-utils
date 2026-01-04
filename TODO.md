# PMACS VPN - Improvement Roadmap

## Current Status (2026-01-04)

### Windows - Fully Working ✅
- CLI and System Tray both work
- Auto-connect, notifications, "Start with Windows"

### macOS - CLI Working ✅, Tray Blocked ⚠️
- **CLI works:** `sudo pmacs-vpn connect`
- **Tray blocked:** Privilege escalation issue (see below)

### Linux - Untested

## Completed

### Core Features
- [x] GlobalProtect auth flow (prelogin → login → getconfig)
- [x] SSL tunnel with async TUN I/O
- [x] Split-tunnel routing for specified hosts
- [x] Username in config file
- [x] Credential caching (--save-password)
- [x] Desktop shortcut workflow (Windows)

### Daemon & Tray Mode (Windows)
- [x] `--daemon` flag for background operation
- [x] Parent does auth, passes token to daemon child
- [x] System tray (`pmacs-vpn tray`) with colored status icons
- [x] Tray checks for cached credentials before connecting
- [x] Poll-based connection status
- [x] Session watchdog with 16hr expiry warnings
- [x] Health monitor detects daemon death after sleep/wake
- [x] Toast notifications (DUO push, connected, disconnected)
- [x] "Start with Windows" menu item

### macOS CLI
- [x] TUN device creation
- [x] Route management
- [x] Keychain credential storage
- [x] Daemon mode (`--daemon`)

---

## Next Priority

### 1. macOS Tray - BLOCKED on Privilege Escalation

**Problem:** The tray app needs to spawn a root daemon for TUN device creation, but macOS's `osascript ... with administrator privileges` blocks until ALL child processes exit - including backgrounded daemons.

**What we tried:**
- `nohup command &` inside osascript → still blocks
- `(command &)` subshell → still blocks
- launchd with WatchPaths trigger → launchctl commands also block
- Spawning osascript async → can't detect user cancellation

**Root cause:** This is by design in macOS. `do shell script ... with administrator privileges` waits for the entire process tree.

**Proper fix: SMAppService (Privileged Helper)**

This is how apps like Tunnelblick and Viscosity handle it:

| Component | Description | Effort |
|-----------|-------------|--------|
| Helper binary | Separate `pmacs-vpn-helper` that runs as root | Medium |
| XPC protocol | Messages: connect, disconnect, status | Small |
| Code signing | Both app and helper must be signed | Medium |
| Plist config | SMAuthorizedClients / SMPrivilegedExecutables | Small |
| Build script | Embed helper in app bundle | Small |

**Estimated effort:** 2-3 days

**Current workaround:** Users run CLI mode:
```bash
sudo pmacs-vpn connect        # foreground
sudo pmacs-vpn connect --daemon  # background
```

---

### 2. Linux Testing
**Status:** Not started
**Effort:** Medium

- [ ] TUN device creation
- [ ] Route commands (`ip route add`)
- [ ] Hosts file management
- [ ] Credential storage (Secret Service)

---

### 3. Code Signing (macOS)
**Status:** Not started
**Effort:** Small-Medium

Benefits:
- No keychain prompts (currently 2 prompts for unsigned app)
- Gatekeeper approval
- Required for SMAppService privileged helper

---

## Nice to Have

### Session Refresh
Re-auth before 16hr expiry without disconnecting.

### Multiple Gateway Profiles
```toml
[profiles.pmacs]
gateway = "psomvpn.uphs.upenn.edu"

[profiles.other]
gateway = "other.example.com"
```

### ESP Mode (IPsec/UDP)
Faster than SSL tunnel, but more complex to implement.

---

*Last updated: 2026-01-04*
