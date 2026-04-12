#!/usr/bin/env bash
# pmacs-vpn disconnect script (Linux/macOS)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

find_exe() {
    local installed="$HOME/.local/bin/pmacs-vpn"
    local debug="$PROJECT_DIR/target/debug/pmacs-vpn"
    local release="$PROJECT_DIR/target/release/pmacs-vpn"

    if [[ -x "$installed" ]]; then echo "$installed"
    elif [[ -x "$release" ]]; then echo "$release"
    elif [[ -x "$debug" ]]; then echo "$debug"
    else
        echo "ERROR: pmacs-vpn binary not found." >&2
        exit 1
    fi
}

EXE="$(find_exe)"
cd "$PROJECT_DIR"

echo ""
echo "========================================"
echo "  PMACS VPN Disconnect"
echo "========================================"
echo ""

if [[ $EUID -ne 0 ]]; then
    exec sudo "$EXE" disconnect
else
    exec "$EXE" disconnect
fi
