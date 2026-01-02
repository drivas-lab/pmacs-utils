# PMACS Utils

Cross-platform toolkit to bypass PMACS full-tunnel VPN using Docker.

## Project Overview

This repo provides a Docker-based workaround for PMACS's GlobalProtect VPN. Instead of routing all traffic through the VPN (full tunnel), we run the VPN in a container and expose SOCKS5/HTTP proxies. Users configure SSH to use the proxy for PMACS hosts only.

## Architecture

```
Local Machine                    Docker Container
─────────────────────────────────────────────────────
Browser/Apps → Normal internet
SSH prometheus → SOCKS5 proxy (8889) → OpenConnect VPN → PMACS
```

## Key Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | OpenConnect container config |
| `.env.example` | Credentials template (user copies to `.env`) |
| `scripts/*.sh` | Bash scripts (Mac/Linux) |
| `scripts/*.ps1` | PowerShell scripts (Windows) |
| `ssh/config.example` | SSH ProxyCommand config |
| `docs/` | Platform-specific setup guides |

## Development Notes

- Uses [wazum/openconnect-proxy](https://github.com/wazum/openconnect-proxy) Docker image
- OpenConnect with `--protocol=gp` for GlobalProtect
- DUO MFA handled via `OPENCONNECT_MFA_CODE=push`
- Proxy ports bound to localhost only (127.0.0.1) for security

## Testing Checklist

Before releases, verify on:
- [ ] macOS with Docker Desktop
- [ ] Windows with Docker Desktop (WSL2 backend)
- [ ] Linux with native Docker

## Common Issues

- **Line endings**: `.gitattributes` handles this, but if scripts fail on Mac, run `dos2unix scripts/*.sh`
- **netcat versions**: BSD vs GNU netcat - Mac users need `brew install netcat`
- **DUO timing**: Container may timeout waiting for push; user needs to approve quickly
