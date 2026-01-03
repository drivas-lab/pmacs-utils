# macOS Setup Guide

## Prerequisites

### 1. Install Homebrew

If you don't have Homebrew:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install OpenConnect

```bash
brew install openconnect
```

### 3. Install vpn-slice

```bash
sudo pip3 install vpn-slice
```

Verify it works:
```bash
sudo vpn-slice --self-test
```

## Manual Connection (Before Scripts Are Ready)

```bash
# Connect to VPN with split tunneling
sudo openconnect psomvpn.uphs.upenn.edu \
  --protocol=gp \
  --user=YOUR_USERNAME \
  -s 'vpn-slice prometheus.pmacs.upenn.edu'

# Enter your PMACS password when prompted
# Enter "push" for the passcode (triggers DUO)
# Approve the DUO push on your phone
```

Keep this terminal open while connected. Ctrl+C to disconnect.

## SSH Setup

Add to `~/.ssh/config`:
```
Host prometheus
    HostName prometheus.pmacs.upenn.edu
    User YOUR_USERNAME
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Then:
```bash
ssh prometheus
```

## SSH Key Setup (Avoid Typing Password)

Generate a key (if you don't have one):
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

With VPN connected, copy your key to the server:
```bash
ssh-copy-id prometheus
```

Or manually:
```bash
cat ~/.ssh/id_ed25519.pub | ssh prometheus "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

Note: Even with SSH keys, PMACS requires DUO approval for each login.

## Troubleshooting

### "vpn-slice: command not found"

Install with sudo:
```bash
sudo pip3 install vpn-slice
```

### "Failed to open tun device"

OpenConnect needs root to create the tunnel:
```bash
sudo openconnect ...
```

### DUO push times out

The DUO approval window is short. Have your phone ready before connecting.

### Connection drops frequently

PMACS has a 2-hour idle timeout. The VPN will disconnect if there's no activity.

### "error: No tun device found"

On older macOS, you may need to install a tun driver. Modern macOS (10.15+) uses utun devices natively.
