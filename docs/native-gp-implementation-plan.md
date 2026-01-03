# Native GlobalProtect Implementation Plan

## Overview

Replace OpenConnect dependency with native GlobalProtect protocol implementation. Single binary, zero dependencies (except wintun.dll on Windows).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        pmacs-vpn                             │
├─────────────────────────────────────────────────────────────┤
│  CLI (main.rs)                                               │
│    └── connect / disconnect / status                         │
├─────────────────────────────────────────────────────────────┤
│  Auth Module (src/gp/auth.rs)                                │
│    └── prelogin → login → getconfig                          │
├─────────────────────────────────────────────────────────────┤
│  Tunnel Module (src/gp/tunnel.rs)                            │
│    └── SSL tunnel establishment + packet I/O                 │
├─────────────────────────────────────────────────────────────┤
│  TUN Device (src/gp/tun.rs)                                  │
│    └── tun-rs wrapper, cross-platform                        │
├─────────────────────────────────────────────────────────────┤
│  Existing Modules (keep as-is)                               │
│    └── platform/ (routing), vpn/hosts.rs, config.rs, state.rs│
└─────────────────────────────────────────────────────────────┘
```

## New Dependencies (add to Cargo.toml)

```toml
[dependencies]
# HTTP client for auth
reqwest = { version = "0.12", features = ["rustls-tls", "cookies"] }

# XML parsing for GP responses
quick-xml = { version = "0.37", features = ["serialize"] }

# TUN device (cross-platform)
tun-rs = { version = "1.4", features = ["async"] }

# TLS for SSL tunnel
tokio-rustls = "0.26"
rustls = "0.23"
webpki-roots = "0.26"
```

---

## Phase 1: Auth Module

**File:** `src/gp/auth.rs`

### 1.1 Data Structures

```rust
/// Pre-login response
pub struct PreloginResponse {
    pub auth_method: AuthMethod,  // SAML or password
    pub label_username: String,
    pub label_password: String,
    pub saml_request: Option<String>,
}

pub enum AuthMethod {
    Password,
    Saml,
}

/// Login response (the "delicious cookie")
pub struct LoginResponse {
    pub auth_cookie: String,
    pub username: String,
    pub domain: String,
    pub portal: String,
    pub gateway_address: String,
}

/// Getconfig response (tunnel parameters)
pub struct TunnelConfig {
    pub mtu: u16,
    pub internal_ip: IpAddr,
    pub internal_ip6: Option<Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub timeout_seconds: u64,
    // For SSL tunnel, we don't need encryption keys
    // (TLS handles it)
}
```

### 1.2 Functions to Implement

```rust
/// Step 1: Check what auth method is required
pub async fn prelogin(gateway: &str) -> Result<PreloginResponse, AuthError>;

/// Step 2: Authenticate with username/password
/// For DUO, password is "password" and passcode is "push"
pub async fn login(
    gateway: &str,
    username: &str,
    password: &str,
    passcode: Option<&str>,  // "push" for DUO
) -> Result<LoginResponse, AuthError>;

/// Step 3: Get tunnel configuration
pub async fn getconfig(
    gateway: &str,
    auth_cookie: &str,
    preferred_ip: Option<IpAddr>,
) -> Result<TunnelConfig, AuthError>;
```

### 1.3 Protocol Details

**Pre-login Request:**
```http
POST /ssl-vpn/prelogin.esp HTTP/1.1
Host: psomvpn.uphs.upenn.edu
User-Agent: PAN GlobalProtect
Content-Type: application/x-www-form-urlencoded

tmp=tmp&clientVer=4100&clientos=Windows
```

**Pre-login Response (XML):**
```xml
<prelogin-response>
  <status>Success</status>
  <authentication-message>Enter login credentials</authentication-message>
  <username-label>Username</username-label>
  <password-label>Password</password-label>
  <saml-auth-method>...</saml-auth-method>  <!-- if SAML -->
</prelogin-response>
```

**Login Request:**
```http
POST /ssl-vpn/login.esp HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=USERNAME&passwd=PASSWORD&passcode=push&computer=HOSTNAME&os-version=Windows
```

**Login Response (XML):**
```xml
<jnlp>
  <application-desc>
    <argument>(auth-cookie)</argument>
    <argument>COOKIE_VALUE_HERE</argument>
    <argument>(portal)</argument>
    <argument>psomvpn.uphs.upenn.edu</argument>
    ...
  </application-desc>
</jnlp>
```

**Getconfig Request:**
```http
POST /ssl-vpn/getconfig.esp HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=USERNAME&portal=PORTAL&authcookie=COOKIE&preferred-ip=0.0.0.0&...
```

---

## Phase 2: TUN Device Wrapper

**File:** `src/gp/tun.rs`

### 2.1 Cross-Platform TUN Creation

```rust
use tun_rs::{DeviceBuilder, AbstractDevice};

pub struct TunDevice {
    device: Box<dyn AbstractDevice>,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given IP configuration
    pub async fn create(config: &TunnelConfig) -> Result<Self, TunError> {
        let device = DeviceBuilder::new()
            .ipv4(config.internal_ip, 24, None)
            .mtu(config.mtu as u16)
            .build_async()?;

        let name = device.name()?.to_string();
        Ok(Self { device, name })
    }

    /// Read a packet from the TUN device (outbound traffic)
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Write a packet to the TUN device (inbound traffic)
    pub async fn write(&self, buf: &[u8]) -> Result<usize, TunError>;

    /// Get the device name (e.g., "utun9" on Mac, "tun0" on Linux)
    pub fn name(&self) -> &str { &self.name }
}
```

### 2.2 Windows: wintun.dll Handling

On Windows, wintun.dll must be in the same directory as the executable. Options:
1. Embed in binary and extract at runtime
2. Ship alongside binary
3. Download on first run

Recommend option 1 for single-binary distribution:

```rust
#[cfg(windows)]
fn ensure_wintun_dll() -> Result<(), Error> {
    let exe_dir = std::env::current_exe()?.parent()?;
    let dll_path = exe_dir.join("wintun.dll");
    if !dll_path.exists() {
        // Embedded at compile time
        let dll_bytes = include_bytes!("../../wintun.dll");
        std::fs::write(&dll_path, dll_bytes)?;
    }
    Ok(())
}
```

---

## Phase 3: SSL Tunnel

**File:** `src/gp/tunnel.rs`

### 3.1 Tunnel Establishment

```rust
pub struct SslTunnel {
    stream: TlsStream<TcpStream>,
    tun: TunDevice,
}

impl SslTunnel {
    /// Connect to gateway and establish SSL tunnel
    pub async fn connect(
        gateway: &str,
        auth_cookie: &str,
        config: &TunnelConfig,
    ) -> Result<Self, TunnelError> {
        // 1. Create TUN device
        let tun = TunDevice::create(config).await?;

        // 2. TCP connect to gateway:443
        let tcp = TcpStream::connect((gateway, 443)).await?;

        // 3. TLS handshake
        let stream = tls_connect(gateway, tcp).await?;

        // 4. Send tunnel request
        // GET /ssl-tunnel-connect.sslvpn?user=...&authcookie=...
        send_tunnel_request(&stream, auth_cookie).await?;

        // 5. Wait for "START_TUNNEL" response
        wait_for_start(&stream).await?;

        Ok(Self { stream, tun })
    }

    /// Run the tunnel (blocking event loop)
    pub async fn run(&mut self) -> Result<(), TunnelError> {
        loop {
            tokio::select! {
                // Packet from TUN → encrypt and send to gateway
                result = self.tun.read(&mut buf) => {
                    let n = result?;
                    self.send_packet(&buf[..n]).await?;
                }
                // Packet from gateway → decrypt and write to TUN
                result = self.recv_packet(&mut buf) => {
                    let n = result?;
                    if n == 0 { /* keepalive */ continue; }
                    self.tun.write(&buf[..n]).await?;
                }
            }
        }
    }
}
```

### 3.2 Packet Framing

SSL tunnel packet format:
```
Offset  Size  Field
0       4     Magic (0x1a2b3c4d)
4       2     Ethertype (0x0800 for IPv4, 0x86dd for IPv6)
6       2     Payload length (big-endian)
8       8     Packet type (0 for data, specific values for control)
16      N     Raw IP packet
```

```rust
const MAGIC: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
const HEADER_SIZE: usize = 16;

fn frame_packet(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + packet.len());
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&[0x08, 0x00]);  // IPv4
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(&[0u8; 8]);  // type = data
    frame.extend_from_slice(packet);
    frame
}

fn parse_frame(frame: &[u8]) -> Result<&[u8], FrameError> {
    if frame.len() < HEADER_SIZE { return Err(FrameError::TooShort); }
    if &frame[0..4] != MAGIC { return Err(FrameError::BadMagic); }
    let len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
    if len == 0 { return Ok(&[]); }  // Keepalive
    Ok(&frame[HEADER_SIZE..HEADER_SIZE + len])
}
```

### 3.3 Keepalives

Send empty frame (len=0) periodically:
```rust
async fn send_keepalive(&mut self) -> Result<(), TunnelError> {
    let keepalive = [
        0x1a, 0x2b, 0x3c, 0x4d,  // magic
        0x00, 0x00,              // ethertype
        0x00, 0x00,              // length = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // type
    ];
    self.stream.write_all(&keepalive).await
}
```

---

## Phase 4: Integration

### 4.1 Update CLI Commands

**Connect command (`src/main.rs`):**
```rust
Commands::Connect { user } => {
    // 1. Load config
    let config = Config::load()?;

    // 2. Get username (from arg, config, or prompt)
    let username = user.or(config.username).unwrap_or_else(prompt_username);

    // 3. Prompt for password
    let password = rpassword::prompt_password("Password: ")?;

    // 4. Auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.gateway).await?;

    println!("Logging in (check phone for DUO push)...");
    let login = gp::auth::login(&config.gateway, &username, &password, Some("push")).await?;

    println!("Getting tunnel config...");
    let tunnel_config = gp::auth::getconfig(&config.gateway, &login.auth_cookie, None).await?;

    // 5. Create tunnel
    println!("Establishing tunnel...");
    let mut tunnel = gp::tunnel::SslTunnel::connect(
        &config.gateway,
        &login.auth_cookie,
        &tunnel_config,
    ).await?;

    // 6. Add routes for configured hosts
    println!("Adding routes...");
    let router = VpnRouter::new(tunnel.tun_name(), &tunnel_config.dns_servers)?;
    for host in &config.hosts {
        router.add_host(host).await?;
    }

    // 7. Update hosts file
    let hosts_mgr = HostsManager::new();
    hosts_mgr.add_entries(&router.resolved_hosts())?;

    // 8. Save state for cleanup
    VpnState::save(&state)?;

    // 9. Run tunnel
    println!("Connected! Press Ctrl+C to disconnect.");
    tunnel.run().await?;
}
```

**Disconnect command:**
```rust
Commands::Disconnect => {
    // Load state, clean up routes/hosts, signal tunnel to stop
    if let Some(state) = VpnState::load()? {
        // Routes and hosts cleanup
        cleanup_from_state(&state)?;
        VpnState::clear()?;
        println!("Disconnected.");
    } else {
        println!("Not connected.");
    }
}
```

### 4.2 Signal Handling

```rust
// In main, wrap tunnel.run() with signal handling
tokio::select! {
    result = tunnel.run() => {
        result?;
    }
    _ = tokio::signal::ctrl_c() => {
        println!("\nDisconnecting...");
    }
}
// Cleanup runs after either branch
cleanup(&state)?;
```

---

## Phase 5: Testing

### 5.1 Unit Tests

- Auth XML parsing (mock responses)
- Packet framing/parsing
- TUN device creation (may need to skip on CI without privileges)

### 5.2 Integration Tests

Manual testing required (needs real VPN credentials):
1. Test auth flow against `psomvpn.uphs.upenn.edu`
2. Test tunnel establishment
3. Test SSH to `prometheus.pmacs.upenn.edu` through tunnel
4. Test disconnect cleanup

---

## File Structure After Implementation

```
src/
├── main.rs              # CLI with connect/disconnect/status
├── lib.rs               # Module exports
├── config.rs            # Config handling (exists)
├── state.rs             # State persistence (exists)
├── gp/                  # NEW: GlobalProtect implementation
│   ├── mod.rs           # Module root
│   ├── auth.rs          # Auth flow (prelogin, login, getconfig)
│   ├── tunnel.rs        # SSL tunnel
│   ├── tun.rs           # TUN device wrapper
│   └── packet.rs        # Packet framing
├── platform/            # Routing (exists, keep as-is)
│   ├── mod.rs
│   ├── mac.rs
│   ├── linux.rs
│   └── windows.rs
└── vpn/                 # Hosts file (exists, keep as-is)
    ├── mod.rs
    ├── routing.rs
    └── hosts.rs
```

---

## Implementation Order

1. **Phase 1.1-1.2**: Auth data structures and prelogin
2. **Phase 1.3**: Login with DUO support
3. **Phase 1.4**: Getconfig
4. **Phase 2**: TUN device wrapper
5. **Phase 3.2**: Packet framing (can unit test)
6. **Phase 3.1**: SSL tunnel establishment
7. **Phase 3.3**: Keepalives
8. **Phase 4**: CLI integration
9. **Phase 5**: Testing

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Protocol changes | We're using well-documented, stable endpoints |
| TLS issues | Use rustls with webpki-roots for proper CA verification |
| DUO timeout | Document that users should have phone ready |
| Windows wintun | Bundle DLL, test on Windows early |
| Privilege errors | Clear error messages, check for admin at startup |

---

## Success Criteria

- [ ] `pmacs-vpn connect -u USERNAME` connects with single command
- [ ] DUO push works (user approves on phone)
- [ ] SSH to prometheus.pmacs.upenn.edu works through tunnel
- [ ] Other traffic (web, etc.) stays on normal network
- [ ] `Ctrl+C` cleanly disconnects
- [ ] Works on Mac, Windows, Linux
- [ ] No external dependencies (single binary + wintun.dll on Windows)
