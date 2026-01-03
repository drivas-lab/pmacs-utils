# PMACS Utils

Toolkit for streamlined PMACS cluster access via split-tunnel VPN.

## Design Principles

1. **UX first** - "Just works" for non-technical users
2. **Cross-platform** - Windows, Mac, Linux from single codebase
3. **Zero dependencies** - Single binary (+ wintun.dll on Windows)
4. **Lightweight for users** - Our code can be robust; user RAM is precious
5. **Best practices** - Error handling, clear messages, defensive coding

## Technical Approach

**Native GlobalProtect implementation** - no OpenConnect dependency.

- Direct GlobalProtect protocol (SSL tunnel mode)
- Cross-platform TUN device via `tun` crate (0.8, async)
- Split-tunnel routing for specified hosts only
- DUO MFA support (server-side RADIUS, we just send "push")
- TLS via rustls (ring crypto backend, no cmake required)

**Language:** Rust (single binary, cross-compiles)

## Knowledge Base

| Doc | Purpose |
|-----|---------|
| [docs/native-gp-implementation-plan.md](docs/native-gp-implementation-plan.md) | **Implementation spec** |
| [docs/pmacs-environment.md](docs/pmacs-environment.md) | PMACS hosts, VPN details |
| [docs/rust-claude-guide.md](docs/rust-claude-guide.md) | Rust dev practices |
| [docs/vpn-slice-analysis.md](docs/vpn-slice-analysis.md) | Routing/hosts approach |

## Target UX

```bash
# Connect (prompts for password, sends DUO push)
pmacs-vpn connect

# Check status
pmacs-vpn status

# Disconnect (Ctrl+C or separate command)
pmacs-vpn disconnect
```

## Configuration

Create `pmacs-vpn.toml` in working directory:

```toml
[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"
username = "yjk"  # Optional, prompts if not set

hosts = [
    "prometheus.pmacs.upenn.edu",
]
```

Or generate default config:
```bash
pmacs-vpn init
```

## Current Status

**Working on Windows** (2026-01-03)

- [x] Full auth flow (password + DUO push)
- [x] SSL tunnel with async TUN I/O
- [x] Split-tunnel routing
- [x] Credential caching (Windows Credential Manager)
- [x] Daemon mode (--daemon flag)
- [x] System tray GUI (pmacs-vpn tray)
- [x] Auto-connect on tray startup (if credentials cached)
- [x] Toast notifications (DUO push, connected, disconnected)
- [x] "Start with Windows" (registry, visible in Task Manager)
- [x] Upfront admin privilege check
- [x] Desktop shortcut workflow
- [x] 70 unit tests, clippy clean
- [x] **SSH to prometheus works!**
- [ ] macOS testing
- [ ] Linux testing

See [TODO.md](TODO.md) for improvement roadmap.

## Architecture

```
src/
├── main.rs          # CLI + daemon spawn logic
├── config.rs        # TOML config
├── credentials.rs   # OS keychain (Windows Credential Manager)
├── state.rs         # Connection state + auth token persistence
├── tray.rs          # System tray GUI
├── gp/              # GlobalProtect protocol
│   ├── auth.rs      # prelogin → login → getconfig
│   ├── tunnel.rs    # SSL tunnel + async event loop
│   ├── tun.rs       # Async TUN device wrapper
│   └── packet.rs    # GP packet framing (16-byte header)
├── platform/        # OS-specific routing
│   ├── mac.rs
│   ├── linux.rs
│   └── windows.rs
└── vpn/
    ├── routing.rs   # DNS + route management
    └── hosts.rs     # /etc/hosts management
```

## Development

```bash
# Build
cargo build

# Test
cargo test

# Lint
cargo clippy -- -D warnings

# Build release
cargo build --release
```

## Gateway Details

- **URL:** `psomvpn.uphs.upenn.edu`
- **Protocol:** GlobalProtect (SSL tunnel mode)
- **Auth:** Password + DUO push
- **Target hosts:** `prometheus.pmacs.upenn.edu` (and others in config)

## Windows: wintun.dll

The binary embeds `wintun.dll` (~420KB) from [wintun.net](https://www.wintun.net/). On first TUN device creation, it auto-extracts to the executable's directory. No manual installation needed.

## Usage (requires admin/root)

```bash
# First time - save password to OS keychain
cargo build --release
./target/release/pmacs-vpn connect --save-password
# Enter password, approve DUO push, password saved

# Future connects - just approve DUO
./target/release/pmacs-vpn connect

# In another terminal
ssh prometheus.pmacs.upenn.edu

# Ctrl+C to disconnect
```

**Desktop shortcut:** See `docs/windows-shortcut.md` for double-click setup.
