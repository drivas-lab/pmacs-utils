# Testing Guide - PMACS VPN

## Prerequisites

### All Platforms
- Valid PMACS credentials (username/password)
- DUO Mobile app configured on your phone
- Network access to `psomvpn.uphs.upenn.edu`

### Windows
- **Administrator privileges** (required for TUN device creation)
- **wintun.dll** - Download from https://www.wintun.net/
  - Place `wintun.dll` in the same directory as `pmacs-vpn.exe`
  - Or in `C:\Windows\System32\`

### macOS
- **Root privileges** (`sudo`)
- No additional dependencies needed

### Linux
- **Root privileges** (`sudo`)
- Kernel TUN/TAP support (should be built-in)

---

## Build Instructions

```bash
# Debug build (faster compile, with debug symbols)
cargo build

# Release build (optimized, single binary)
cargo build --release

# The binary will be at:
# - Debug: target/debug/pmacs-vpn (or pmacs-vpn.exe on Windows)
# - Release: target/release/pmacs-vpn (or pmacs-vpn.exe on Windows)
```

---

## Test Plan

### Phase 1: Basic Functionality

#### 1.1 Configuration Generation
```bash
# Generate default config
./pmacs-vpn init

# Verify pmacs-vpn.toml was created
cat pmacs-vpn.toml
```

**Expected output:**
```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"

hosts = ["prometheus.pmacs.upenn.edu"]
```

#### 1.2 Status Check (Disconnected)
```bash
./pmacs-vpn status
```

**Expected output:**
```
VPN Status: Not connected
```

#### 1.3 Connection Test
```bash
# Windows: Run as Administrator
# macOS/Linux: Run with sudo

# Windows:
.\pmacs-vpn.exe connect -u USERNAME

# macOS/Linux:
sudo ./pmacs-vpn connect -u USERNAME
```

**Expected flow:**
1. Prompts for password (type your PMACS password)
2. Shows "Authenticating..."
3. Shows "Logging in (check phone for DUO push if prompted)..."
4. **Check your phone** - approve DUO push notification
5. Shows "Getting tunnel configuration..."
6. Shows "Establishing tunnel..."
7. Shows "Adding routes..."
8. Shows "Connected! Press Ctrl+C to disconnect."
9. Displays TUN device name and internal IP

**Look for errors:**
- Authentication failures
- TLS/SSL errors
- TUN device creation failures
- Routing errors

#### 1.4 Verify Connection

**In a new terminal (keep VPN running):**

```bash
# Test connectivity to PMACS host
ping prometheus.pmacs.upenn.edu

# Test SSH (if you have SSH access)
ssh USERNAME@prometheus.pmacs.upenn.edu

# Check DNS resolution
nslookup prometheus.pmacs.upenn.edu

# Verify split-tunnel (google should still work)
ping google.com
```

**Expected:**
- `prometheus.pmacs.upenn.edu` is reachable
- Other internet traffic (google.com) still works
- No impact on normal internet access

#### 1.5 Status Check (Connected)
```bash
./pmacs-vpn status
```

**Expected output:**
```
VPN Status: Connected
  Tunnel: utun9 (or tun0, or similar)
  Gateway: <IP address>
  Routes: 1
    prometheus.pmacs.upenn.edu -> <IP>
  Hosts entries: 1
```

#### 1.6 Graceful Disconnect

**In the VPN terminal:**
```bash
# Press Ctrl+C
```

**Expected:**
- Shows "Disconnecting..."
- Cleans up routes
- Removes hosts entries
- Deletes state file
- Exits cleanly

#### 1.7 Verify Cleanup
```bash
# Check status
./pmacs-vpn status
# Should show: VPN Status: Not connected

# Verify hosts file is clean (Windows)
type C:\Windows\System32\drivers\etc\hosts

# Verify hosts file is clean (macOS/Linux)
cat /etc/hosts

# Should NOT contain "# BEGIN pmacs-vpn" section
```

---

### Phase 2: Error Handling

#### 2.1 Wrong Password
```bash
./pmacs-vpn connect -u USERNAME
# Enter incorrect password
```

**Expected:**
- Authentication error
- Clear error message
- Exits gracefully (no crash)

#### 2.2 DUO Rejection
```bash
./pmacs-vpn connect -u USERNAME
# Enter correct password
# Reject DUO push on phone
```

**Expected:**
- Login failure message
- Exits gracefully

#### 2.3 Network Interruption
```bash
# Connect successfully
# Disconnect network (WiFi off, unplug ethernet)
# Wait 2-3 minutes
```

**Expected:**
- Tunnel detects disconnection
- Shows "Tunnel disconnected" or similar
- Cleans up and exits

#### 2.4 Duplicate Connection Attempt
```bash
# Start first connection
./pmacs-vpn connect -u USERNAME

# In another terminal, try to connect again
./pmacs-vpn connect -u USERNAME
```

**Expected:**
- Second attempt should either:
  - Detect existing connection and warn
  - Or fail to create TUN device with clear error

---

### Phase 3: Extended Testing

#### 3.1 Long-Running Connection
```bash
# Connect and leave running for 1+ hour
./pmacs-vpn connect -u USERNAME

# Monitor keepalives in logs with -v flag
./pmacs-vpn -v connect -u USERNAME
```

**Expected:**
- Keepalive packets sent every 30 seconds (visible with -v)
- Connection remains stable
- No memory leaks (check with `top` / Task Manager)

#### 3.2 Multiple Hosts
```bash
# Edit pmacs-vpn.toml
# Add more hosts to the list

[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"

hosts = [
    "prometheus.pmacs.upenn.edu",
    "another-host.pmacs.upenn.edu",
    "third-host.pmacs.upenn.edu"
]

# Connect and verify all routes are added
./pmacs-vpn connect -u USERNAME
./pmacs-vpn status
```

**Expected:**
- All hosts resolved and routed
- All hosts entries added
- Can reach all hosts

#### 3.3 Reconnection
```bash
# Connect
./pmacs-vpn connect -u USERNAME

# Disconnect (Ctrl+C)

# Immediately reconnect
./pmacs-vpn connect -u USERNAME
```

**Expected:**
- Clean reconnection
- No state file conflicts
- No stale routes/hosts entries

---

### Phase 4: Platform-Specific Tests

#### Windows-Specific
1. Verify wintun.dll detection error if missing
2. Test with Windows Firewall enabled
3. Test with antivirus software active

#### macOS-Specific
1. Verify utun device naming (utunN)
2. Test with built-in firewall enabled
3. Check System Preferences → Network for TUN interface

#### Linux-Specific
1. Verify tun0/tun1 device creation
2. Test on different distributions (if available)
3. Check `ip route` for added routes

---

## Troubleshooting

### "Permission denied" errors
- Windows: Run as Administrator
- macOS/Linux: Use `sudo`

### "wintun.dll not found" (Windows)
- Download from https://www.wintun.net/
- Place in same directory as executable

### "Failed to create TUN device"
- Check admin/root privileges
- Verify another VPN isn't using TUN device
- On Linux: `modprobe tun`

### "Authentication failed"
- Verify username/password
- Check DUO mobile app is configured
- Test VPN credentials via web portal first

### "Connection timeout"
- Check network connectivity to gateway
- Verify firewall allows HTTPS (port 443)
- Check corporate proxy settings

### Cleanup if VPN crashes
```bash
# Manual cleanup
./pmacs-vpn disconnect

# Or manually check state
# Windows:
type %USERPROFILE%\.pmacs-vpn\state.json

# macOS/Linux:
cat ~/.pmacs-vpn/state.json
```

---

## Logging

Enable verbose logging:
```bash
./pmacs-vpn -v connect -u USERNAME
```

This shows:
- TLS handshake details
- Packet I/O (bytes sent/received)
- Keepalive messages
- Routing operations
- Hosts file modifications

---

## Success Criteria

- [ ] Can authenticate with password + DUO
- [ ] TUN device created successfully
- [ ] Routes added for configured hosts
- [ ] Can ping/SSH to PMACS hosts
- [ ] Other internet traffic unaffected (split-tunnel works)
- [ ] Keepalives maintain connection
- [ ] Ctrl+C disconnects cleanly
- [ ] All state/routes/hosts cleaned up on disconnect
- [ ] No memory leaks during long sessions
- [ ] Clear error messages for common failures

---

## Known Limitations

1. **Windows Only:** Requires wintun.dll (not bundled)
2. **Root Required:** Cannot create TUN devices without elevation
3. **Single Connection:** Cannot run multiple instances
4. **Manual DUO:** No automatic retry if DUO push is missed

---

## Reporting Issues

When reporting issues, include:
1. Platform (Windows/macOS/Linux) and version
2. Full command used
3. Error message (full text)
4. Output of `pmacs-vpn -v connect ...` (verbose logs)
5. Contents of `~/.pmacs-vpn/state.json` if crash occurred
6. Network environment (corporate, home, etc.)
