# PMACS Utils

**Bypass PMACS's full-tunnel VPN without affecting your normal internet traffic.**

PMACS requires GlobalProtect VPN to access cluster resources, but GlobalProtect routes *all* your traffic through the VPN (full tunnel). This is slow and annoying.

This tool runs the VPN inside a Docker container and exposes a proxy, so only the traffic you explicitly route through it goes over the VPN. Your browser, Spotify, everything else stays on your normal connection.

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  Your Computer                                                       │
│                                                                      │
│  ┌──────────────┐     Normal traffic      ┌──────────────────────┐  │
│  │   Browser    │ ──────────────────────> │  Your ISP / Internet │  │
│  │   Spotify    │                         └──────────────────────┘  │
│  │   etc.       │                                                    │
│  └──────────────┘                                                    │
│                                                                      │
│  ┌──────────────┐                         ┌──────────────────────┐  │
│  │   Terminal   │                         │   Docker Container   │  │
│  │              │                         │  ┌────────────────┐  │  │
│  │  ssh prom... │ ── SOCKS5 proxy ──────> │  │  OpenConnect   │  │  │
│  │              │    localhost:8889       │  │  VPN Client    │  │  │
│  └──────────────┘                         │  └───────┬────────┘  │  │
│                                           │          │           │  │
│                                           │          │ VPN       │  │
│                                           │          │ Tunnel    │  │
│                                           └──────────┼───────────┘  │
└──────────────────────────────────────────────────────┼──────────────┘
                                                       │
                                                       ▼
                                            ┌──────────────────────┐
                                            │   PMACS Network      │
                                            │  ┌────────────────┐  │
                                            │  │  prometheus    │  │
                                            │  │  (cluster)     │  │
                                            │  └────────────────┘  │
                                            └──────────────────────┘
```

**Key insight:** The VPN runs inside Docker. Only traffic you explicitly send through the proxy (localhost:8889) goes over the VPN tunnel. Everything else on your machine is unaffected.

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Mac, Windows, or Linux)
- `netcat` for SSH proxy (`brew install netcat` on Mac, usually pre-installed on Linux)

### 1. Clone and Configure

```bash
git clone https://github.com/drivaslab/pmacs-utils.git
cd pmacs-utils

# Create your config file
cp .env.example .env

# Edit .env with your PMACS credentials
# OPENCONNECT_USER=your_pennkey
# OPENCONNECT_PASSWORD=your_password (or leave blank for prompt)
```

### 2. Set Up SSH

**Option A: Automatic (Mac/Linux)**
```bash
./ssh/setup.sh
```

**Option B: Manual**
Add to `~/.ssh/config`:
```
Host prometheus
    HostName prometheus.pmacs.upenn.edu
    User YOUR_USERNAME
    ProxyCommand nc -x 127.0.0.1:8889 %h %p
    ServerAliveInterval 60
```

Create the sockets directory:
```bash
mkdir -p ~/.ssh/sockets
chmod 700 ~/.ssh/sockets
```

### 3. Connect

```bash
# Start VPN
./scripts/connect.sh

# Approve DUO push on your phone

# SSH to PMACS
ssh prometheus
```

### 4. Disconnect

```bash
./scripts/disconnect.sh
```

## Commands

| Script | Description |
|--------|-------------|
| `./scripts/connect.sh` | Start VPN container and wait for proxy |
| `./scripts/disconnect.sh` | Stop VPN container |
| `./scripts/status.sh` | Check VPN and proxy status |

**Windows (PowerShell):**
```powershell
.\scripts\connect.ps1
.\scripts\disconnect.ps1
.\scripts\status.ps1
```

## Configuration

### .env File

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENCONNECT_URL` | Yes | VPN gateway (default: `psomvpn.uphs.upenn.edu`) |
| `OPENCONNECT_USER` | Yes | Your PMACS username |
| `OPENCONNECT_PASSWORD` | No | Leave blank to enter interactively |
| `OPENCONNECT_MFA_CODE` | No | `push` for DUO, or TOTP code |
| `OPENCONNECT_OPTIONS` | No | Additional OpenConnect flags |

### Proxy Ports

| Port | Protocol | Use For |
|------|----------|---------|
| 8889 | SOCKS5 | SSH, general TCP |
| 8888 | HTTP | Browsers, curl |

## Troubleshooting

### "Connection refused" on port 8889

VPN container isn't running or hasn't connected yet:
```bash
./scripts/status.sh       # Check status
docker logs pmacs-vpn     # View VPN logs
```

### DUO push not arriving

Check container logs for the authentication prompt:
```bash
docker logs -f pmacs-vpn
```

### "nc: invalid option -- 'x'"

Your system has BSD netcat instead of GNU netcat. Options:

**Mac:**
```bash
brew install netcat
```

**Or use ncat (from nmap):**
```
ProxyCommand ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
```

### SSH connection hangs

1. Verify VPN is connected: `./scripts/status.sh`
2. Test proxy directly: `curl --proxy socks5h://127.0.0.1:8889 http://prometheus.pmacs.upenn.edu`
3. Check container logs: `docker logs pmacs-vpn`

### Docker not running

Start Docker Desktop, then try again.

## Platform Notes

See detailed guides:
- [Windows Setup](docs/WINDOWS.md)
- [macOS Setup](docs/MAC.md)

## How This Compares to Official GlobalProtect

| Aspect | Official GlobalProtect | This Tool |
|--------|------------------------|-----------|
| Tunnel type | Full tunnel (all traffic) | Split tunnel (only what you route) |
| Internet speed | Slower (through VPN) | Normal speed |
| Privacy | All traffic visible to PMACS | Only PMACS traffic visible |
| Setup | Install app + connect | Docker + one-time SSH config |
| Disconnect to browse | Yes | No |

## Security Notes

- Your PMACS credentials are stored in `.env` (git-ignored)
- The Docker container runs privileged (required for VPN tunnel creation)
- Only localhost can access the proxy ports (bound to 127.0.0.1)
- VPN traffic is encrypted the same as official GlobalProtect

## Contributing

PRs welcome. Please test on your platform before submitting.

## License

MIT
