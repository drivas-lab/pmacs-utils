#!/usr/bin/env bash
#
# Connect to PMACS VPN via Docker container
# Works on: macOS, Linux, Windows (Git Bash/WSL)
#
# Usage: ./connect.sh [--logs]
#   --logs    Attach to container logs after starting (see DUO prompt)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check prerequisites
check_prereqs() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        log_info "Install Docker Desktop: https://docker.com/products/docker-desktop"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Start Docker Desktop and try again"
        exit 1
    fi

    if [[ ! -f "$PROJECT_DIR/.env" ]]; then
        log_error ".env file not found"
        log_info "Copy .env.example to .env and fill in your credentials:"
        log_info "  cp .env.example .env"
        exit 1
    fi
}

# Check if already connected
check_existing() {
    if docker ps --format '{{.Names}}' | grep -q '^pmacs-vpn$'; then
        log_warn "VPN container is already running"
        log_info "Use './disconnect.sh' to stop, or './status.sh' to check status"
        exit 0
    fi
}

# Start the VPN container
start_vpn() {
    log_info "Starting PMACS VPN container..."

    cd "$PROJECT_DIR"
    docker compose up -d

    log_ok "Container started"
    log_info ""
    log_info ">>> CHECK YOUR PHONE FOR DUO PUSH <<<"
    log_info ""
}

# Wait for proxy to be ready
wait_for_proxy() {
    log_info "Waiting for VPN tunnel and proxy..."

    local max_attempts=30
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        if nc -z 127.0.0.1 8889 2>/dev/null; then
            log_ok "SOCKS5 proxy is ready on localhost:8889"
            log_ok "HTTP proxy is ready on localhost:8888"
            return 0
        fi

        ((attempt++))
        sleep 2
    done

    log_error "Proxy did not become ready within 60 seconds"
    log_info "Check logs with: docker logs pmacs-vpn"
    return 1
}

# Test connection
test_connection() {
    log_info "Testing connection to PMACS..."

    # Try to resolve a PMACS host through the proxy
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 5 --proxy socks5h://127.0.0.1:8889 http://prometheus.pmacs.upenn.edu &> /dev/null; then
            log_ok "Successfully reached PMACS network"
        else
            log_warn "Could not verify PMACS connectivity (may still work)"
        fi
    fi
}

# Main
main() {
    echo ""
    echo "=========================================="
    echo "  PMACS VPN Connect"
    echo "=========================================="
    echo ""

    check_prereqs
    check_existing
    start_vpn

    # Show logs if requested
    if [[ "${1:-}" == "--logs" ]]; then
        log_info "Attaching to logs (Ctrl+C to detach)..."
        docker logs -f pmacs-vpn
    else
        wait_for_proxy
        test_connection

        echo ""
        log_ok "VPN connected! You can now SSH to PMACS hosts."
        log_info "Example: ssh prometheus"
        log_info ""
        log_info "To see VPN logs: docker logs pmacs-vpn"
        log_info "To disconnect:   ./scripts/disconnect.sh"
    fi
}

main "$@"
