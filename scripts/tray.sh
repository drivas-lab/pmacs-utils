#!/usr/bin/env bash
# pmacs-vpn system tray (Linux/macOS)
# Launches VPN tray in the background
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
        echo "  Build it: cd $PROJECT_DIR && cargo build" >&2
        exit 1
    fi
}

EXE="$(find_exe)"
cd "$PROJECT_DIR"

# On macOS, tray runs as normal user (elevation happens internally)
# On Linux, tray needs to run as root for connect/disconnect
if [[ "$(uname)" == "Linux" && $EUID -ne 0 ]]; then
    exec sudo "$EXE" tray "$@"
else
    exec "$EXE" tray "$@"
fi
