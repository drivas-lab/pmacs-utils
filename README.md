# PMACS Utils

Lightweight VPN bypass for PMACS cluster access. Uses native OpenConnect with split tunneling — no Docker, no VMs.

## How It Works

```
Your Mac
├── Browser, Spotify, etc. → Normal internet (unchanged)
└── ssh prometheus         → OpenConnect tunnel → PMACS
```

Only PMACS traffic goes through the VPN. Everything else uses your normal connection.

## Requirements

- macOS (Windows support coming later)
- Homebrew
- PMACS credentials + DUO

## Quick Start

```bash
# Clone
git clone https://github.com/drivaslab/pmacs-utils.git
cd pmacs-utils

# Run setup (installs dependencies, configures SSH)
./scripts/setup.sh

# Connect to VPN
./scripts/connect.sh
# Approve DUO push on your phone

# SSH to cluster
ssh prometheus
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup.sh` | One-time setup: install deps, configure SSH, generate keys |
| `scripts/connect.sh` | Start VPN connection |
| `scripts/disconnect.sh` | Stop VPN connection |

## What Gets Installed

- **openconnect** — Open-source VPN client (via Homebrew)
- **vpn-slice** — Split-tunnel routing (via pip)

## Platform Support

| Platform | Status |
|----------|--------|
| macOS | Supported |
| Windows | Coming soon (WSL-based) |
| Linux | Should work, untested |

## Troubleshooting

See [docs/MAC.md](docs/MAC.md) for detailed macOS instructions and common issues.

## License

MIT
