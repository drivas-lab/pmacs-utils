#!/usr/bin/env bash
# pmacs-vpn connect script (Linux/macOS)
# Runs VPN in foreground (keeps terminal open while connected)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find binary: installed location first, then build output
find_exe() {
    local installed="$HOME/.local/bin/pmacs-vpn"
    local debug="$PROJECT_DIR/target/debug/pmacs-vpn"
    local release="$PROJECT_DIR/target/release/pmacs-vpn"

    if [[ -x "$installed" ]]; then echo "$installed"
    elif [[ -x "$release" ]]; then echo "$release"
    elif [[ -x "$debug" ]]; then echo "$debug"
    else
        echo "ERROR: pmacs-vpn binary not found." >&2
        echo "  Build it: cd $PROJECT_DIR && cargo build" >&2
        exit 1
    fi
}

EXE="$(find_exe)"
cd "$PROJECT_DIR"

# Check if already connected
if "$EXE" status 2>&1 | grep -q "VPN Status: Connected"; then
    echo "VPN is already connected!"
    "$EXE" status
    echo ""
    echo "To disconnect: pmacs-vpn disconnect"
    exit 0
fi

echo ""
echo "========================================"
echo "  PMACS VPN Connect"
echo "========================================"
echo ""
echo "  1. Enter your password when prompted"
echo "  2. Approve the DUO push on your phone"
echo "  3. Keep this terminal open while connected"
echo "  4. Press Ctrl+C to disconnect"
echo ""

# Connect requires root for TUN device and routes
if [[ $EUID -ne 0 ]]; then
    exec sudo "$EXE" connect "$@"
else
    exec "$EXE" connect "$@"
fi
