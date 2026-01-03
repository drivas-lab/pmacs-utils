# vpn-slice Analysis

Source: https://github.com/dlenski/vpn-slice

## What vpn-slice Does

vpn-slice is a replacement for OpenConnect's default `vpnc-script`. Instead of routing all traffic through VPN (full tunnel), it only routes specified hosts/subnets (split tunnel).

## How OpenConnect Calls Scripts

OpenConnect invokes the script with environment variables:

| Variable | Purpose |
|----------|---------|
| `VPNGATEWAY` | VPN gateway IP |
| `TUNDEV` | Tunnel device name (e.g., `utun9`) |
| `INTERNAL_IP4_ADDRESS` | IP assigned to client |
| `INTERNAL_IP4_DNS` | VPN's DNS server(s) |
| `reason` | Lifecycle event: `connect`, `disconnect`, `reconnect` |

## Core Flow

### On Connect

1. Configure tunnel device (IP address, MTU)
2. Resolve specified hostnames using VPN's DNS
3. Add routes for resolved IPs → tunnel device
4. Add `/etc/hosts` entries for hostnames
5. Fork to background, parent exits (returns control to openconnect)

### On Disconnect

1. Remove routes
2. Remove `/etc/hosts` entries
3. Cleanup any firewall rules

## macOS Implementation

**Routing:**
```bash
/sbin/route add 172.16.38.40/32 -interface utun9
```

**Hosts file:** `/etc/hosts` (same as Linux)

**Split DNS:** Creates files in `/etc/resolver/<domain>` with nameserver entries

**Firewall:** Uses `pfctl` (Packet Filter)

## What We Need (Minimal)

For our use case, we only need:

1. **Parse env vars** - `TUNDEV`, `INTERNAL_IP4_DNS`, `VPNGATEWAY`
2. **DNS lookup** - Resolve hostnames via VPN's DNS server
3. **Add route** - `route add <ip>/32 -interface <tundev>`
4. **Add hosts entry** - Append to `/etc/hosts`
5. **Cleanup on exit** - Remove route, remove hosts entry

We don't need:
- Split DNS configuration
- Firewall rules
- IPv6 support (for now)
- Complex subnet handling

## Estimated Complexity

~100-150 lines of Python for macOS. Windows adds another ~50-100 lines for platform differences.
