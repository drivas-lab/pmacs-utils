# PMACS Utils

Toolkit for streamlined PMACS cluster access via split-tunnel VPN.

## Design Principles

1. **UX first** - "Just works" for non-technical users
2. **Cross-platform** - Mac first, then Windows/Linux
3. **No hardcoding** - Config-driven
4. **Lightweight for users** - Our code can be robust; user RAM is precious
5. **Best practices** - Error handling, clear messages, defensive coding

## Technical Approach

**Split-tunnel VPN** using OpenConnect + custom routing logic (inspired by vpn-slice).

- OpenConnect connects to GlobalProtect (`psomvpn.uphs.upenn.edu`)
- Our routing module adds routes only for specified hosts (e.g., `prometheus.pmacs.upenn.edu`)
- Everything else uses normal internet

**Language:** Rust (single binary, cross-compiles to Mac/Windows/Linux)

## Knowledge Base

| Doc | Purpose |
|-----|---------|
| [docs/pmacs-environment.md](docs/pmacs-environment.md) | PMACS hosts, VPN details, SSH config |
| [docs/vpn-slice-analysis.md](docs/vpn-slice-analysis.md) | How vpn-slice works, what we need |
| [docs/rust-claude-guide.md](docs/rust-claude-guide.md) | Rust development best practices with Claude |

## Quick Reference

```bash
# Manual test (working)
sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
  -s 'vpn-slice prometheus.pmacs.upenn.edu'

# Then in another terminal
ssh prometheus.pmacs.upenn.edu
```

## Current Status

- [x] Validated split-tunnel approach works
- [x] Analyzed vpn-slice source
- [ ] Implement Python toolkit
