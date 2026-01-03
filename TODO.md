# PMACS VPN - Improvement Roadmap

## Current Status (2026-01-03)

Native GlobalProtect client working on Windows:
- ✅ Full auth flow (password + DUO push)
- ✅ SSL tunnel with bidirectional traffic
- ✅ Split-tunnel routing
- ✅ DNS resolution via VPN
- ✅ Hosts file management
- ✅ State persistence and cleanup
- ✅ Username in config
- ✅ Credential caching (Windows Credential Manager)
- ✅ Desktop shortcut workflow

## Completed

### 1. Save Username in Config ✅
Config supports `username` field - no need to type each time.

### 2. Credential Caching ✅
- `--save-password` stores password in Windows Credential Manager
- `--forget-password` clears stored password
- `forget-password` subcommand for management

### 3. Desktop Shortcut ✅
- `scripts/connect.ps1` - auto-elevating PowerShell script
- `docs/windows-shortcut.md` - setup guide

## Next Priority

### 4. Background/Daemon Mode
**Status:** TODO
**Effort:** Medium

Run VPN in background, freeing the terminal:
```powershell
pmacs-vpn connect --daemon
pmacs-vpn status
pmacs-vpn disconnect
```

Implementation:
- Windows: Use `windows-service` crate or detach process
- Unix: Fork to background, write PID file

### 5. Watchdog / Keep-Alive Enhancement
**Status:** TODO
**Effort:** Small-Medium

Prevent idle timeout (server disconnects after 2hrs idle):
- Current: 30s keepalive interval
- Enhance: Configurable interval, activity-based keepalives
- Detect impending timeout, warn user
- Auto-reconnect on disconnect

Session lifetime (16hr max) handling:
- Track session start time
- Warn before session expires
- Prompt for re-auth when needed

### 6. Better Connect Output
**Status:** TODO
**Effort:** Small

Show cleaner status during connection:
```
Authenticating... ✓
Waiting for DUO push... ✓
Establishing tunnel... ✓
Adding routes... ✓
Connected to PMACS VPN (10.156.56.38)
```

## Cross-Platform

### 7. macOS Support
**Status:** TODO
**Effort:** Medium

- Test TUN device creation (utun)
- Test routing commands (`route add`)
- Test hosts file (`/etc/hosts`)
- Build and test on Mac

### 8. Linux Support
**Status:** TODO
**Effort:** Medium

- Test TUN device creation
- Test routing (`ip route add`)
- Test hosts file
- Package for common distros

## Nice to Have

### 9. System Tray App (Windows)
**Status:** TODO
**Effort:** Large

GUI for:
- Connect/disconnect
- Show status
- View logs
- Quick access to SSH

### 10. Auto-Connect on Startup
**Status:** TODO
**Effort:** Medium

- Windows: Scheduled task or service
- macOS: LaunchAgent
- Linux: systemd user service

### 11. Multiple Gateway Profiles
**Status:** TODO
**Effort:** Small

Support multiple VPN configs:
```toml
[profiles.pmacs]
gateway = "psomvpn.uphs.upenn.edu"
username = "yjk"
hosts = ["prometheus.pmacs.upenn.edu"]

[profiles.other]
gateway = "other.vpn.example.com"
```

```powershell
pmacs-vpn connect --profile pmacs
```

## Technical Debt

### 12. ESP Mode Support
**Status:** TODO
**Effort:** Large

Currently SSL-only. ESP (IPsec/UDP) would be faster:
- Parse ESP keys from getconfig
- Implement ESP encapsulation
- UDP transport instead of TLS

### 13. IPv6 Support
**Status:** Partial
**Effort:** Medium

- TUN device supports IPv6
- Need to test routing
- Need to handle IPv6 DNS

### 14. Better Error Messages
**Status:** TODO
**Effort:** Small

- "Access denied" → "Run as Administrator"
- "DNS failed" → "Check VPN connection, try IP directly"
- Suggest fixes for common errors

## Integration

### 15. VS Code Integration
**Status:** Works (no changes needed)
**Effort:** Documentation only

VS Code Remote SSH works automatically because:
1. We add hosts file entries
2. We add routes
3. SSH uses system networking

Document: use `prometheus-direct` SSH config (no ProxyJump).

---

## Priority Order

1. Username in config (immediate UX win)
2. macOS support (expand user base)
3. Background mode (better terminal UX)
4. Credential caching (reduce friction)
5. System tray (polish)
