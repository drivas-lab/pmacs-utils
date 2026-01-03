# PMACS Environment Reference

## VPN

| VPN | Gateway | Status |
|-----|---------|--------|
| GlobalProtect | `psomvpn.uphs.upenn.edu` | Current |
| Ivanti | `juneau.med.upenn.edu` | Legacy |

### Authentication Flow

1. Connect to `psomvpn.uphs.upenn.edu`
2. Enter PMACS username + password
3. Enter `push` for DUO (or `sms`, `phone`, 6-digit code)
4. Approve on phone
5. VPN connects

### Why VPN is Required

Without VPN, internal hostnames don't resolve (internal DNS only). VPN provides:
- DNS resolution for `*.pmacs.upenn.edu`
- Network routing to PMACS subnets

## Clusters

### HPC (High Performance Computing)

| Host | Purpose |
|------|---------|
| `consign.pmacs.upenn.edu` | Head node (job submission) |
| `mercury.pmacs.upenn.edu` | File transfer, first login |

### LPC (Limited Performance Computing)

| Host | Purpose |
|------|---------|
| `scisub.pmacs.upenn.edu` | Submit host |
| `sciget.pmacs.upenn.edu` | Access host |
| `prometheus.pmacs.upenn.edu` | **Our lab's node** |

## SSH

- Protocol: SSH v2, port 22
- Auth: Password or SSH key (DUO may still be required)
- Config tip: `ServerAliveInterval 60` prevents timeout
- Password expiration: 180 days

## Tested Split Tunnel Config

```bash
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s 'vpn-slice prometheus.pmacs.upenn.edu'
```

**Verified working:**
- Default route stays on local network
- Only prometheus (172.16.38.40) routes through VPN tunnel (utun9)
- Normal internet traffic unaffected

## Documentation Sources

- [GlobalProtect Setup Guide](https://www.med.upenn.edu/pmacs/client-computing/psom-vpn/globalprotect-vpn-setup-guide)
- [HPC Wiki - Login](https://hpcwiki.pmacs.upenn.edu/wiki/index.php/HPC:Login)
- [HPC Quick Start](https://www.med.upenn.edu/hpc/quick-start-technical-guide.html)
