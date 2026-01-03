# GlobalProtect Auth Flow Investigation

**Date:** 2026-01-03
**Status:** RESOLVED - Tunnel Established

## Server Details

- **Gateway:** psomvpn.uphs.upenn.edu (170.212.0.240)
- **Auth method:** Password + DUO MFA (push)
- **Endpoints:** `/ssl-vpn/prelogin.esp`, `/ssl-vpn/login.esp`, `/ssl-vpn/getconfig.esp`

## Working Flow (Final)

### 1. Prelogin
```
POST /ssl-vpn/prelogin.esp
Body: tmp=tmp&clientVer=4100&clientos=Windows

→ 200 OK, XML: status=Success, auth method=Password
```

### 2. Login (credentials)
```
POST /ssl-vpn/login.esp
Body: user=yjk&passwd=<password>&jnlpReady=jnlpReady&ok=Login&direct=yes&...

→ 200 OK, HTML challenge:
  var respStatus = "Challenge";
  var respMsg = "Enter passcode:";
  thisForm.inputStr.value = "<16-char-hex-token>";
```

### 3. MFA Step (DUO push)
```
POST /ssl-vpn/login.esp
Body: user=yjk&passwd=push&inputStr=<token>&jnlpReady=jnlpReady&ok=Login&direct=yes&...

→ DUO push sent, user approves
→ 200 OK, JNLP XML with auth-cookie (positional format)
```

### 4. Getconfig
```
POST /ssl-vpn/getconfig.esp
Body: user=yjk&authcookie=<32-hex>&portal=<gateway>&protocol-version=p1&...

→ 200 OK, XML with tunnel config (IP, DNS, routes, IPsec keys)
```

### 5. Tunnel Connect
```
GET /ssl-tunnel-connect.sslvpn?user=yjk&authcookie=<32-hex>

→ START_TUNNEL
```

## Critical Fixes Applied

### 1. Missing Required Parameters (SOLVED empty 200 response)

Without these parameters, server returned empty 200 after MFA:

| Parameter | Value | Required |
|-----------|-------|----------|
| `jnlpReady` | `jnlpReady` | **YES** |
| `ok` | `Login` | **YES** |
| `direct` | `yes` | **YES** |
| `ipv6-support` | `yes` | Recommended |

**Lesson:** The GP protocol requires these literal strings. Missing them = silent failure.

### 2. JNLP Positional Format (SOLVED missing auth-cookie error)

PMACS server returns positional JNLP, not labeled:
```xml
<jnlp><application-desc>
  <argument></argument>                    <!-- [0] empty -->
  <argument>ec85fe94925569db...</argument> <!-- [1] auth-cookie (32 hex) -->
  <argument>651e643201afcb35...</argument> <!-- [2] persistent-cookie (40 hex) -->
  <argument>gateway-name</argument>        <!-- [3] gateway -->
  <argument>yjk</argument>                 <!-- [4] username -->
  <argument>profile</argument>             <!-- [5] auth profile -->
  <argument>vsys1</argument>               <!-- [6] vsys -->
  <argument>pmacs</argument>               <!-- [7] domain -->
  ...
</application-desc></jnlp>
```

**Lesson:** Don't assume labeled format like `(auth-cookie)`, `value`. Check for positional.

### 3. Getconfig Parameters (SOLVED "errors getting SSL/VPN config")

Must send full user info from login response:
- `user` = actual username (not empty!)
- `portal` = gateway from login
- `domain` = domain from login
- `protocol-version` = `p1`
- `enc-algo` = `aes-256-gcm,aes-128-gcm,aes-128-cbc`
- `hmac-algo` = `sha1`
- `computer` = hostname

### 4. Tunnel Request (SOLVED "Invalid user name")

Must include username in URL:
```
GET /ssl-tunnel-connect.sslvpn?user=yjk&authcookie=<cookie>
```

### 5. DNS Resolver Runtime Conflict (SOLVED panic)

`trust_dns_resolver::Resolver` (sync) creates its own runtime inside Tokio async context → panic.

**Fix:** Use `std::net::ToSocketAddrs` instead.

## Current Status

**Tunnel established successfully!**

### Fixed (2026-01-03)
- ✅ VPN DNS resolution - Routes now resolve via VPN's DNS servers (128.91.22.200, 172.16.50.10)
- ✅ Direct IP routing - `add_ip_route()` method for testing without DNS
- ✅ State directory on Windows - Uses `USERPROFILE` fallback

### Ready to Test
- [ ] Full connection with SSH to prometheus
- [ ] Verify packet flow through tunnel

## Reference

- [GP Protocol Doc](https://github.com/dlenski/openconnect/blob/master/PAN_GlobalProtect_protocol_doc.md)
- [gpclient source](https://github.com/yuezk/GlobalProtect-openconnect)
- gpclient's `gp_params.rs` shows all required parameters

---

## Test Procedure

### Prerequisites
1. Admin/elevated terminal (for TUN device and routes)
2. PMACS VPN credentials
3. Phone with DUO app for MFA

### Build
```powershell
cd C:\drivaslab\pmacs-utils
cargo build --release
```

### Test Steps

#### 1. Connect with Verbose Logging
```powershell
# Run as Administrator
.\target\release\pmacs-vpn.exe -v connect -u YOUR_USERNAME
```

**Expected output:**
```
Authenticating...
Auth method: Password
Logging in (check phone for DUO push if prompted)...
Login successful: YOUR_USERNAME
Getting tunnel configuration...
Tunnel config: IP=10.x.x.x MTU=1400
Establishing tunnel...
START_TUNNEL received
Adding routes...
  Using VPN DNS: 128.91.22.200, 172.16.50.10
  Added route: prometheus.pmacs.upenn.edu -> 172.16.38.40
Connected! Press Ctrl+C to disconnect.
TUN device: wintun
Internal IP: 10.x.x.x
```

#### 2. Verify Route (in another terminal)
```powershell
# Check route exists
route print | findstr "prometheus"
# or
route print | findstr "172.16"
```

#### 3. Test SSH Connection
```powershell
# In another terminal while VPN is connected
ssh prometheus.pmacs.upenn.edu
# or if DNS still fails, try direct IP:
ssh 172.16.38.40
```

#### 4. Debug: Check Packet Flow
If SSH hangs, check tunnel logs for packet activity:
- `TUN read X bytes` = outgoing packets
- `Gateway read X bytes` = incoming packets
- `Sending keepalive` = tunnel maintenance

#### 5. Disconnect
Press Ctrl+C in the VPN terminal, or run:
```powershell
.\target\release\pmacs-vpn.exe disconnect
```

### Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| "DNS resolution failed" | VPN DNS unreachable | Check tunnel is up, try direct IP |
| "Failed to add route" | Not running as admin | Run terminal as Administrator |
| SSH hangs | Route missing or packets not flowing | Check `route print`, verify TUN activity |
| "Invalid user name" | Username not in tunnel request | Already fixed in code |
| Empty 200 response | Missing `jnlpReady` param | Already fixed in code |

### Debug Mode
For maximum logging:
```powershell
$env:RUST_LOG="debug"
.\target\release\pmacs-vpn.exe -v connect -u YOUR_USERNAME
```
