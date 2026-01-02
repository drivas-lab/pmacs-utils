# macOS Setup Guide

## Prerequisites

### 1. Install Docker Desktop

Download from: https://www.docker.com/products/docker-desktop/

Or with Homebrew:
```bash
brew install --cask docker
```

After installation:
1. Start Docker from Applications
2. Grant permissions when prompted
3. Wait for Docker to fully start (menu bar icon stops animating)
4. Verify: `docker --version`

### 2. Install a SOCKS-capable netcat

macOS includes BSD netcat, but it lacks the `-x` (proxy) option. You have two options:

**Option A: ncat from nmap (recommended)**
```bash
brew install nmap
```
Then use this ProxyCommand in SSH config:
```
ProxyCommand ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
```

**Option B: GNU netcat**
```bash
brew install netcat
```
GNU netcat is keg-only, so add it to your PATH in `~/.zshrc`:
```bash
export PATH="/opt/homebrew/opt/netcat/bin:$PATH"  # Apple Silicon
# or: export PATH="/usr/local/opt/netcat/bin:$PATH"  # Intel Mac
```
Then reload: `source ~/.zshrc`

## Installation

```bash
# Clone the repo
git clone https://github.com/drivaslab/pmacs-utils.git
cd pmacs-utils

# Create your config
cp .env.example .env

# Edit with your credentials
nano .env
# or: open .env  (opens in default editor)
```

## SSH Configuration

### Automatic Setup (recommended)

```bash
./ssh/setup.sh
```

This will:
1. Detect if you have `ncat` or GNU `nc` installed
2. Create `~/.ssh/sockets` directory
3. Back up existing SSH config
4. Add PMACS configuration with the correct ProxyCommand
5. Prompt for your username

### Manual Setup

Add to `~/.ssh/config`:

```
Host prometheus
    HostName prometheus.pmacs.upenn.edu
    User YOUR_USERNAME
    # Use ncat (recommended) or nc depending on what you installed
    ProxyCommand ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

Create sockets directory:
```bash
mkdir -p ~/.ssh/sockets
chmod 700 ~/.ssh/sockets
```

## Usage

```bash
# Start VPN
./scripts/connect.sh

# Approve DUO push on your phone

# SSH to cluster
ssh prometheus

# Check status
./scripts/status.sh

# Disconnect
./scripts/disconnect.sh
```

## Common Issues

### "nc: invalid option -- 'x'"

You're using BSD netcat instead of GNU netcat.

**Fix 1:** Install GNU netcat:
```bash
brew install netcat
```

**Fix 2:** Use ncat instead (edit `~/.ssh/config`):
```
ProxyCommand ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
```

### Docker not starting

1. Check System Preferences > Security & Privacy > Privacy > Full Disk Access
2. Ensure Docker has permission
3. Try: `killall Docker && open -a Docker`

### "Cannot connect to the Docker daemon"

Docker Desktop isn't running. Start it from Applications.

### Connection hangs after "Waiting for VPN tunnel"

Check container logs:
```bash
docker logs -f pmacs-vpn
```

Usually means:
- DUO push wasn't approved
- Wrong credentials
- Network issue

### Permission denied on scripts

Make scripts executable:
```bash
chmod +x scripts/*.sh ssh/*.sh
```

### SSH connection drops frequently

Increase keepalive settings in `~/.ssh/config`:
```
ServerAliveInterval 30
ServerAliveCountMax 5
```

## Tips

### Create an alias

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias pmacs-vpn="cd ~/path/to/pmacs-utils && ./scripts/connect.sh"
alias pmacs-off="cd ~/path/to/pmacs-utils && ./scripts/disconnect.sh"
```

Then: `pmacs-vpn` to connect, `pmacs-off` to disconnect.

### Auto-start on login (optional)

If you always need PMACS access, create a Launch Agent:

`~/Library/LaunchAgents/com.pmacs.vpn.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pmacs.vpn</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/pmacs-utils/scripts/connect.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Load with: `launchctl load ~/Library/LaunchAgents/com.pmacs.vpn.plist`

### iTerm2 Profile

Create a dedicated iTerm2 profile that auto-connects:
1. Preferences > Profiles > +
2. Name: "PMACS"
3. Command: `/path/to/pmacs-utils/scripts/connect.sh && ssh prometheus`

### VS Code Remote SSH

The Remote-SSH extension works with this setup. Just ensure VPN is connected first, then connect to `prometheus`.
