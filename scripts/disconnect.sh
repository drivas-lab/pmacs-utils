#!/usr/bin/env bash
#
# Disconnect from PMACS VPN
# Works on: macOS, Linux, Windows (Git Bash/WSL)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

main() {
    echo ""
    echo "=========================================="
    echo "  PMACS VPN Disconnect"
    echo "=========================================="
    echo ""

    if ! docker ps --format '{{.Names}}' | grep -q '^pmacs-vpn$'; then
        log_info "VPN container is not running"
        exit 0
    fi

    log_info "Stopping VPN container..."

    cd "$PROJECT_DIR"
    docker compose down

    log_ok "VPN disconnected"
}

main
