# P1 Sprint Handoff

## Completed in This Sprint

### P1.1: OpenConnect Script Mode ✅

Implemented `pmacs-vpn script` command for OpenConnect integration:

```bash
# How it works
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s 'pmacs-vpn script'
```

**Files created:**
- `src/openconnect/mod.rs` - Module root with documentation
- `src/openconnect/env.rs` - Environment variable parsing (TUNDEV, VPNGATEWAY, etc.)
- `src/openconnect/script.rs` - Connect/disconnect handlers
- `src/state.rs` - State persistence (~/.pmacs-vpn/state.json)

**Key features:**
- Parses OpenConnect environment variables
- Uses VPN DNS servers for hostname resolution
- Adds routes via `route -n add -host <IP> -interface <tundev>`
- Updates /etc/hosts with managed section markers
- Saves state for crash recovery
- Handles reconnect by cleaning up first

### P1.4: State Persistence ✅

State file format (`~/.pmacs-vpn/state.json`):
```json
{
  "version": 1,
  "tunnel_device": "utun9",
  "gateway": "10.0.0.1",
  "routes": [{"hostname": "prometheus.pmacs.upenn.edu", "ip": "172.16.38.40"}],
  "hosts_entries": [{"hostname": "prometheus.pmacs.upenn.edu", "ip": "172.16.38.40"}],
  "connected_at": "1704000000"
}
```

### Tests

41 tests total, all passing:
- 7 env parsing tests
- 2 script handler tests
- 6 state persistence tests
- Previous 26 tests (config, platform, vpn modules)

---

## What's Working Now

```bash
# 1. Build the binary
cargo build --release

# 2. Copy to PATH (or use full path)
sudo cp target/release/pmacs-vpn /usr/local/bin/

# 3. Create config (optional - uses defaults)
pmacs-vpn init

# 4. Connect with OpenConnect
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s 'pmacs-vpn script'

# 5. Check status
pmacs-vpn status
```

---

## Remaining P1 Work

### P1.2: VPN DNS Resolution - DONE (integrated)
Already using VPN DNS via `INTERNAL_IP4_DNS` environment variable.

### P1.3: macOS Route Commands - DONE
Updated to use `-interface` syntax for tunnel devices.

---

## Next Sprint: P2 (User Experience)

### P2.1: Connect Command (Wrapper Mode)
Spawn OpenConnect automatically instead of requiring manual invocation:
```rust
// In main.rs Connect handler:
// 1. Build pmacs-vpn binary path
// 2. Spawn: openconnect ... -s '<path> script'
// 3. Handle password/DUO prompts (passthrough or PTY)
```

**Key considerations:**
- Need to pass through stdin for password entry
- May need PTY for interactive prompts
- Should show OpenConnect output to user

### P2.2: Disconnect Command
Find and kill OpenConnect process:
```rust
// 1. Read state file to confirm VPN is active
// 2. Find openconnect process (pgrep or /proc scan)
// 3. Send SIGTERM
// 4. OpenConnect will invoke 'pmacs-vpn script' with reason=disconnect
```

### P2.3: Status Command - PARTIALLY DONE
Basic implementation exists. Could enhance with:
- Check if OpenConnect process is running
- Show tunnel interface details (IP, MTU)
- Show uptime

### P2.4: Error Messages
Add user-friendly error messages for:
- Not running as root
- OpenConnect not installed
- VPN gateway unreachable
- DNS resolution failures

---

## File Structure After P1

```
src/
├── main.rs              # CLI with script command
├── lib.rs               # Module exports
├── config.rs            # Config handling
├── state.rs             # NEW: State persistence
├── openconnect/         # NEW: OpenConnect integration
│   ├── mod.rs
│   ├── env.rs           # Environment parsing
│   └── script.rs        # Connect/disconnect handlers
├── platform/
│   ├── mod.rs
│   ├── mac.rs           # UPDATED: -interface routing
│   ├── linux.rs
│   └── windows.rs
└── vpn/
    ├── mod.rs
    ├── routing.rs
    └── hosts.rs
```

---

## Testing the Implementation

### Manual Test Sequence

1. **Build:**
   ```bash
   cargo build --release
   ```

2. **Test script mode parsing (without VPN):**
   ```bash
   reason=pre-init ./target/release/pmacs-vpn script
   # Should exit successfully (pre-init is a no-op)
   ```

3. **Full integration test (requires VPN credentials):**
   ```bash
   sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
     -s './target/release/pmacs-vpn script' -v

   # In another terminal:
   pmacs-vpn status
   ssh prometheus.pmacs.upenn.edu
   ```

4. **Verify cleanup:**
   ```bash
   # After Ctrl+C on OpenConnect:
   pmacs-vpn status  # Should show "Not connected"
   cat /etc/hosts    # Should not have pmacs-vpn section
   ```

---

## Known Limitations

1. **No wrapper mode yet** - Must run OpenConnect manually
2. **No orphan cleanup** - If state file exists but VPN isn't connected, need manual cleanup
3. **No signal handlers** - If pmacs-vpn crashes, routes/hosts may be left behind
4. **Single config location** - Only checks ./pmacs-vpn.toml or ~/.pmacs-vpn/config.toml

---

## Commits in This Sprint

1. `bb6a12f` - Add VPN state persistence module
2. `17ef8b6` - Add OpenConnect integration module
3. `34c6190` - Integrate script mode into CLI

---

## Quick Reference

```bash
# Build
cargo build --release

# Test
cargo test

# Lint
cargo clippy -- -D warnings

# Manual VPN test
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s './target/release/pmacs-vpn script'
```
