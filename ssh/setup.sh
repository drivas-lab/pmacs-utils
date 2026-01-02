#!/usr/bin/env bash
#
# Set up SSH configuration for PMACS access
# Works on: macOS, Linux
#
# This script:
#   1. Creates ~/.ssh/sockets directory (for connection multiplexing)
#   2. Backs up existing SSH config
#   3. Appends PMACS config to ~/.ssh/config
#   4. Prompts for your username

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_DIR="$HOME/.ssh"
SSH_CONFIG="$SSH_DIR/config"
SOCKETS_DIR="$SSH_DIR/sockets"
EXAMPLE_CONFIG="$SCRIPT_DIR/config.example"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo ""
echo "=========================================="
echo "  PMACS SSH Setup"
echo "=========================================="
echo ""

# Check for SOCKS-capable netcat
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS: BSD nc doesn't support -x, need ncat or GNU netcat
    if command -v ncat &> /dev/null; then
        USE_NCAT=true
        log_ok "Found ncat (recommended for macOS)"
    elif command -v nc &> /dev/null && nc -h 2>&1 | grep -q -- '-x'; then
        USE_NCAT=false
        log_ok "Found GNU netcat"
    else
        log_warn "No SOCKS-capable netcat found"
        log_info "Install ncat: brew install nmap"
        log_info "Then re-run this script"
        echo ""
    fi
else
    # Linux: system nc usually works
    if ! command -v nc &> /dev/null; then
        log_warn "netcat (nc) not found"
        log_info "Install with: sudo apt install netcat"
        echo ""
    fi
fi

# Get username
read -p "Enter your PMACS username: " username
if [[ -z "$username" ]]; then
    echo "Username cannot be empty"
    exit 1
fi

# Create directories
log_info "Creating SSH directories..."
mkdir -p "$SSH_DIR"
mkdir -p "$SOCKETS_DIR"
chmod 700 "$SSH_DIR"
chmod 700 "$SOCKETS_DIR"
log_ok "Created $SOCKETS_DIR"

# Backup existing config
if [[ -f "$SSH_CONFIG" ]]; then
    backup="$SSH_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$SSH_CONFIG" "$backup"
    log_ok "Backed up existing config to $backup"
fi

# Check if PMACS config already exists
if grep -q "prometheus.pmacs.upenn.edu" "$SSH_CONFIG" 2>/dev/null; then
    log_warn "PMACS configuration already exists in $SSH_CONFIG"
    echo ""
    read -p "Overwrite existing PMACS config? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Aborted"
        exit 0
    fi
    # Remove existing PMACS block (simple approach - just warn)
    log_warn "Please manually remove the old PMACS section before running again"
    exit 1
fi

# Append config
log_info "Adding PMACS configuration to $SSH_CONFIG..."

# Determine ProxyCommand based on available tools
if [[ "${USE_NCAT:-false}" == "true" ]]; then
    PROXY_CMD="ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p"
else
    PROXY_CMD="nc -x 127.0.0.1:8889 %h %p"
fi

# Extract just the config section (after the instructions)
{
    echo ""
    echo "# PMACS Utils - Added $(date +%Y-%m-%d)"
    sed -n '/^# PMACS HOSTS/,/^# NOTES/p' "$EXAMPLE_CONFIG" | head -n -1
} | sed "s/YOUR_USERNAME_HERE/$username/g" | sed "s|nc -x 127.0.0.1:8889 %h %p|$PROXY_CMD|g" >> "$SSH_CONFIG"

chmod 600 "$SSH_CONFIG"
log_ok "Configuration added"

echo ""
log_ok "SSH setup complete!"
echo ""
log_info "To connect (after starting VPN):"
echo "  1. Start VPN:  ./scripts/connect.sh"
echo "  2. SSH:        ssh prometheus"
echo ""
