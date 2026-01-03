# Session Handoff — 2026-01-03 Windows Implementation Complete

## Completed This Session

### Critical Fixes
1. **GP packet type field** (`a45ae7d`) - bytes 8-15 must be `0x01...` for data packets, not all zeros
2. **Windows route gateway** (`218a33a`) - use `0.0.0.0` for on-link routing, not TUN IP

### Infrastructure
3. **Async TUN refactor** (`4e88a47`) - tun crate 0.6→0.8, non-blocking I/O with tokio::select!
4. **DNS socket binding** (`7466a5d`) - IP_UNICAST_IF for Windows interface binding
5. **MTU 0 handling** (`a765a1b`) - server returns 0, default to 1400

### UX Improvements
6. **Username in config** (`a8b9d7b`) - saves typing each connect
7. **Credential caching** (`0702b16`) - stores password in Windows Credential Manager
8. **Desktop shortcut** - PowerShell script + documentation

## Current State

**Windows: Fully Working**
- Auth flow (password + DUO push) ✓
- SSL tunnel with bidirectional traffic ✓
- Split-tunnel routing ✓
- SSH to prometheus.pmacs.upenn.edu ✓
- VS Code Remote SSH works ✓

**Tests:** 61 passing, clippy clean

## Usage

```powershell
# First time - save password
pmacs-vpn connect --save-password

# Future connects - just approve DUO
pmacs-vpn connect

# Or use desktop shortcut (see docs/windows-shortcut.md)
```

## Key Files Changed

| File | Purpose |
|------|---------|
| `src/gp/packet.rs` | Fixed packet type field |
| `src/platform/windows.rs` | Fixed route gateway |
| `src/gp/tun.rs` | Async TUN device |
| `src/gp/tunnel.rs` | tokio::select! event loop |
| `src/credentials.rs` | NEW - keyring integration |
| `scripts/connect.ps1` | NEW - desktop shortcut script |

## Next Steps (TODO.md)

1. **Background/daemon mode** - free terminal after connect
2. **Watchdog enhancement** - prevent idle timeout
3. **macOS support** - test TUN, routing, hosts
4. **Better connect output** - progress indicators

## Technical Notes

### Root Cause of Original Issue
The GP packet header (16 bytes) has a "type" field at bytes 8-15:
- Data packets: `0x01 00 00 00 00 00 00 00`
- Keepalives: `0x00 00 00 00 00 00 00 00`

We were sending all zeros, making gateway treat data as keepalives.

Reference: OpenConnect `gpst.c`

### SSH Integration
User's existing SSH config has two entries:
- `prometheus` - ProxyJump through ubuntu-vpn (VM-based VPN)
- `prometheus-direct` - direct connection (native VPN)

With native VPN running, use `prometheus-direct` or just `ssh prometheus.pmacs.upenn.edu`.

## Untracked Handoffs

The following handoffs from earlier debugging sessions are untracked:
- `handoff-2026-01-03-async-tun-refactor.md`
- `handoff-2026-01-03-dns-binding-diagnosis.md`
- `handoff-2026-01-03-investigation-report.md` (Gemini's analysis)
- `handoff-2026-01-03-route-gateway-diagnosis.md`

These can be synthesized into documentation when implementing macOS support.
