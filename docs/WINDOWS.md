# Windows Setup Guide

## Prerequisites

### 1. Install Docker Desktop

Download from: https://www.docker.com/products/docker-desktop/

During installation:
- Choose **WSL 2 backend** (recommended) or Hyper-V backend
- If prompted, install WSL 2 Linux kernel update

After installation:
1. Start Docker Desktop
2. Wait for it to fully start (whale icon stops animating)
3. Verify: Open PowerShell and run `docker --version`

### 2. Install Git (if needed)

Download from: https://git-scm.com/download/win

Git Bash is included and provides a Unix-like shell for running the `.sh` scripts.

## Installation

### Using PowerShell

```powershell
cd C:\path\to\your\projects
git clone https://github.com/drivaslab/pmacs-utils.git
cd pmacs-utils

# Create config
copy .env.example .env
notepad .env  # Edit with your credentials
```

### Using Git Bash

```bash
cd /c/path/to/your/projects
git clone https://github.com/drivaslab/pmacs-utils.git
cd pmacs-utils

cp .env.example .env
# Edit .env with your credentials
```

## SSH Configuration

### Option 1: Git Bash SSH

Git Bash includes OpenSSH. Add to `~/.ssh/config` (usually `C:\Users\YourName\.ssh\config`):

```
Host prometheus
    HostName prometheus.pmacs.upenn.edu
    User YOUR_USERNAME
    ProxyCommand connect -S 127.0.0.1:8889 %h %p
    ServerAliveInterval 60
```

The `connect` proxy command is included with Git for Windows.

### Option 2: Windows OpenSSH

Windows 10/11 includes OpenSSH. Edit `C:\Users\YourName\.ssh\config`:

```
Host prometheus
    HostName prometheus.pmacs.upenn.edu
    User YOUR_USERNAME
    ProxyCommand C:\path\to\ncat.exe --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p
    ServerAliveInterval 60
```

You'll need to install ncat (from Nmap): https://nmap.org/download.html

### Option 3: Use Git Bash for SSH only

Even if you use PowerShell for everything else, you can use Git Bash just for SSH:

```bash
# In Git Bash
ssh prometheus
```

## Running Scripts

### PowerShell (recommended for Windows)

```powershell
.\scripts\connect.ps1
.\scripts\status.ps1
.\scripts\disconnect.ps1
```

### Git Bash

```bash
./scripts/connect.sh
./scripts/status.sh
./scripts/disconnect.sh
```

## Common Issues

### "Docker daemon is not running"

Start Docker Desktop and wait for it to fully initialize.

### "Access denied" or permission errors

Run PowerShell as Administrator, or check Docker Desktop settings for file sharing permissions.

### Scripts won't run (PowerShell execution policy)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### WSL 2 not installed

Docker Desktop should prompt you, but if not:

```powershell
wsl --install
# Restart computer
wsl --set-default-version 2
```

### Can't connect after VPN starts

1. Check Windows Firewall isn't blocking Docker
2. Verify ports aren't in use: `netstat -an | findstr "8889"`
3. Try restarting Docker Desktop

## Tips

### Create shortcuts

Create a `.bat` file on your desktop for quick access:

**connect-vpn.bat:**
```batch
@echo off
cd /d C:\path\to\pmacs-utils
powershell -ExecutionPolicy Bypass -File scripts\connect.ps1
pause
```

### Use Windows Terminal

Windows Terminal provides a better experience than the default PowerShell window. Install from Microsoft Store.

### VS Code Integration

If you use VS Code, you can run scripts from the integrated terminal and SSH directly with the Remote-SSH extension.
