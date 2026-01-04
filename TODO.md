# PMACS VPN - Improvement Roadmap

## Current Status (2026-01-03)

Native GlobalProtect client **working on Windows**:
- Full auth flow (password + DUO push)
- SSL tunnel with bidirectional traffic
- Split-tunnel routing
- DNS resolution via VPN
- Hosts file management
- State persistence and cleanup
- Credential caching (Windows Credential Manager)
- Daemon mode (background operation)
- System tray with GUI control
- Upfront admin privilege check

## Completed

### Core Features
- [x] GlobalProtect auth flow (prelogin → login → getconfig)
- [x] SSL tunnel with async TUN I/O
- [x] Split-tunnel routing for specified hosts
- [x] Username in config file
- [x] Credential caching (--save-password)
- [x] Desktop shortcut workflow

### Daemon & Tray Mode
- [x] `--daemon` flag for background operation
- [x] Parent does auth, passes token to daemon child
- [x] System tray (`pmacs-vpn tray`) with colored status icons
- [x] Tray checks for cached credentials before connecting
- [x] Poll-based connection status (replaced hardcoded 5s wait)
- [x] Session watchdog with 16hr expiry warnings
- [x] Health monitor detects daemon death after sleep/wake

### UX Improvements
- [x] Upfront admin privilege check with clear error message
- [x] Interactive first-run config setup
- [x] "Using cached password" feedback
- [x] `tray.ps1` script with auto-elevation
- [x] Improved connect.ps1 with status check
- [x] Auto-connect on tray startup (if credentials cached)
- [x] Toast notifications (DUO push, connected, disconnected)
- [x] "Start with Windows" menu item (registry-based, visible in Task Manager)
- [x] Setup notification for new users without credentials

## Next Priority

### 1. macOS Testing
**Status:** Not started
**Effort:** Medium

Test on macOS:
- [ ] TUN device creation (utun)
- [ ] Route commands (`route add`)
- [ ] Hosts file (`/etc/hosts`)
- [ ] Credential storage (Keychain)

### 2. Linux Testing
**Status:** Not started
**Effort:** Medium

Test on Linux:
- [ ] TUN device creation
- [ ] Route commands (`ip route add`)
- [ ] Hosts file
- [ ] Credential storage (Secret Service)

### 3. Better Error Messages
**Status:** Partial
**Effort:** Small

Translate system errors to user-friendly messages:
- [x] Admin privilege check
- [ ] DNS resolution failures
- [ ] Network timeout hints
- [ ] DUO timeout guidance
- [ ] Credential expiry (prompt to run `--save-password` again)

## Nice to Have

### 4. Session Refresh (Re-auth Before Expiry)
The official GP client prompts for DUO re-auth ~15 mins before session expires, extending without disconnect.

To implement:
- Detect approaching expiry (already have warnings)
- Re-run auth flow with cached password + new DUO push
- Get fresh authcookie and continue tunnel (or reconnect)
- Needs investigation: can we refresh in-place or must reconnect?

### 5. Multiple Gateway Profiles
```toml
[profiles.pmacs]
gateway = "psomvpn.uphs.upenn.edu"

[profiles.other]
gateway = "other.example.com"
```

### 6. Tray UX Polish
- [ ] Reconnect button after unexpected disconnect (vs clicking Connect again)
- [ ] Connection uptime in tooltip
- [ ] Network transition handling (WiFi→Ethernet, etc.)

## Technical Debt

### ESP Mode Support
Currently SSL-only. ESP (IPsec/UDP) would be faster:
- Parse ESP keys from getconfig
- Implement ESP encapsulation
- UDP transport instead of TLS

### IPv6 Support
- TUN device supports IPv6
- Routing not tested
- DNS handling not tested

---

*Last updated: 2026-01-03*
