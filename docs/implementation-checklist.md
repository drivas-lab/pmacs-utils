# Implementation Checklist

## Current State

✅ Project scaffold with CLI
✅ Config module (load/save TOML)
✅ Platform routing managers (macOS/Linux/Windows)
✅ VPN routing with DNS resolution
✅ Hosts file management
✅ Unit tests (26 tests passing)

---

## Priority 1: Core Functionality (MVP)

These are required for basic split-tunnel VPN to work.

### P1.1: OpenConnect Script Mode
- [ ] Parse OpenConnect environment variables (`TUNDEV`, `INTERNAL_IP4_DNS`, `VPNGATEWAY`, `reason`)
- [ ] Implement `connect` handler (configure tunnel, add routes, update hosts)
- [ ] Implement `disconnect` handler (cleanup routes, restore hosts)
- [ ] Add `--script` CLI mode for OpenConnect to invoke us

### P1.2: VPN DNS Resolution
- [ ] Use VPN's DNS server (`INTERNAL_IP4_DNS`) for hostname resolution
- [ ] Fall back to system DNS if VPN DNS fails
- [ ] Cache resolved IPs for disconnect cleanup

### P1.3: macOS Route Commands
- [ ] Update `MacRoutingManager` to use `-interface <tundev>` syntax
- [ ] Handle route conflicts (route already exists)
- [ ] Test with actual VPN tunnel device

### P1.4: State Persistence
- [ ] Track active routes/hosts in state file (`~/.pmacs-vpn/state.json`)
- [ ] Enable cleanup even if process crashes
- [ ] Implement `status` command to show active state

---

## Priority 2: User Experience

Make it pleasant to use.

### P2.1: Connect Command (Wrapper Mode)
- [ ] Spawn OpenConnect with our binary as the script
- [ ] Pass through username (`-u` flag)
- [ ] Handle authentication prompts (password, DUO)
- [ ] Show connection progress

### P2.2: Disconnect Command
- [ ] Find running OpenConnect process
- [ ] Send SIGTERM for graceful shutdown
- [ ] Verify cleanup completed

### P2.3: Status Command
- [ ] Show VPN connection status
- [ ] List active routes
- [ ] List managed hosts entries
- [ ] Show tunnel device info

### P2.4: Error Messages
- [ ] Clear error messages for common failures
- [ ] Suggest fixes (e.g., "run with sudo", "check VPN credentials")
- [ ] Verbose mode (`-v`) for debugging

---

## Priority 3: Robustness

Handle edge cases and failures gracefully.

### P3.1: Privilege Handling
- [ ] Detect if running as root (required for routes)
- [ ] Provide clear message if not root
- [ ] Consider sudo wrapper or setuid approaches

### P3.2: Cleanup Guarantees
- [ ] Signal handlers (SIGTERM, SIGINT) for graceful cleanup
- [ ] Orphan cleanup on startup (leftover state from crash)
- [ ] Atomic hosts file updates (write to temp, rename)

### P3.3: Reconnect Handling
- [ ] Handle `reconnect` reason from OpenConnect
- [ ] Preserve routes across brief disconnects
- [ ] Update routes if IPs changed

---

## Priority 4: Cross-Platform

Extend to Linux and Windows.

### P4.1: Linux Support
- [ ] Test `ip route` commands on Linux
- [ ] Handle different tunnel device naming (`tun0` vs `utun9`)
- [ ] Package for common distros

### P4.2: Windows Support
- [ ] Implement Windows route commands
- [ ] Handle Windows hosts file path
- [ ] Test with Windows GlobalProtect client

---

## Priority 5: Polish

Nice-to-haves for production use.

### P5.1: Config Improvements
- [ ] XDG config path support (`~/.config/pmacs-vpn/`)
- [ ] Multiple host profiles
- [ ] Custom route additions (subnets, not just hosts)

### P5.2: Logging
- [ ] Structured logging with tracing
- [ ] Log file rotation
- [ ] Syslog integration (macOS/Linux)

### P5.3: Distribution
- [ ] Homebrew formula (macOS)
- [ ] GitHub releases with binaries
- [ ] Installation script

---

## Quick Reference: MVP Commands

After P1 is complete:

```bash
# Script mode (called by OpenConnect)
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s 'pmacs-vpn --script'

# Wrapper mode (spawns OpenConnect)
sudo pmacs-vpn connect -u USERNAME

# Check status
pmacs-vpn status

# Disconnect
sudo pmacs-vpn disconnect
```

---

## Next Action

Start with **P1.1: OpenConnect Script Mode** - this is the core functionality that makes everything else work.
