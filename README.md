# pmacs-vpn

Split-tunnel VPN utility for PMACS.

The official GlobalProtect VPN routes all of your traffic through PMACS.
This slow downs everything, blocks access to Gmail, and is generally creepy.

This is a lightweight alternative that keeps your non-PMACS traffic private.
Written in Rust and pure spite.

# Quickstart

## macOS

```bash
# Download and install
curl -L https://github.com/DrivasLab/pmacs-utils/releases/latest/download/pmacs-vpn-macos -o pmacs-vpn
chmod +x pmacs-vpn
sudo mv pmacs-vpn /usr/local/bin/

# First-time setup
pmacs-vpn init

# Connect (enter VPN password when prompted, approve DUO push)
sudo pmacs-vpn connect
```

**Test it worked:** Open a new terminal and run `ssh prometheus.pmacs.upenn.edu`

## Tips

### Skip the sudo password

Add Touch ID for sudo on your Mac. One-time setup in your terminal:
```bash
sudo sed -i '' '2i\
auth       sufficient     pam_tid.so
' /etc/pam.d/sudo
```

### Run in background

```bash
sudo pmacs-vpn connect --background   # runs in background
pmacs-vpn status                      # check if connected
sudo pmacs-vpn disconnect             # stop
```

**Keychain popup asking for password:** Click "Always Allow" so it doesn't ask again.

### Set up SSH keys for automatic connection:

```bash
ssh-keygen -t ed25519
ssh-copy-id prometheus.pmacs.upenn.edu
```

---

## Why not just use GlobalProtect?

| | pmacs-vpn | GlobalProtect |
|---|-----------|---------------|
| **Memory (connected)** | 12 MB | 230 MB |
| **Memory (idle)** | 0 MB | 73 MB |
| **Install size** | 5 MB | 162 MB |
| **Background processes** | None | 2-3 (always) |
| **Blocks Gmail** | No | Yes |
| **Watches all your traffic** | No | Yes |

GlobalProtect runs three background processes 24/7 eating 73 MB of RAM even when you're not using it.
When connected, it balloons to 230 MB and routes *everything* through Penn Medicine's network—your
email, your Spotify, your Google searches. All of it.

pmacs-vpn connects only when you need it, routes only PMACS hosts through the tunnel, and exits
cleanly when you're done. Your other traffic stays between you and your ISP.


## Windows

Download `pmacs-vpn.exe` from [Releases](https://github.com/DrivasLab/pmacs-utils/releases/latest), then run as Administrator:

```cmd
pmacs-vpn init
pmacs-vpn connect
```

### System tray

```cmd
pmacs-vpn tray
```

---

Note: If anyone has an Apple developer account and is willing to help with CodeSign, please contact yunjun.kang@pennmedicine.upenn.edu
