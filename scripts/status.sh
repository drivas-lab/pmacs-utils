#!/usr/bin/env bash
#
# Check PMACS VPN status
# Works on: macOS, Linux, Windows (Git Bash/WSL)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "=========================================="
echo "  PMACS VPN Status"
echo "=========================================="
echo ""

# Check Docker
echo -e "${BLUE}Docker:${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "  ${RED}Not installed${NC}"
    exit 1
elif ! docker info &> /dev/null; then
    echo -e "  ${YELLOW}Installed but not running${NC}"
    exit 1
else
    echo -e "  ${GREEN}Running${NC}"
fi

echo ""

# Check container
echo -e "${BLUE}VPN Container:${NC}"
if docker ps --format '{{.Names}}' | grep -q '^pmacs-vpn$'; then
    status=$(docker inspect --format='{{.State.Status}}' pmacs-vpn 2>/dev/null)
    health=$(docker inspect --format='{{.State.Health.Status}}' pmacs-vpn 2>/dev/null || echo "no healthcheck")
    uptime=$(docker inspect --format='{{.State.StartedAt}}' pmacs-vpn 2>/dev/null | cut -d'.' -f1)

    echo -e "  Status: ${GREEN}${status}${NC}"
    echo -e "  Health: ${health}"
    echo -e "  Started: ${uptime}"
else
    echo -e "  ${YELLOW}Not running${NC}"
    echo ""
    echo "To connect: ./scripts/connect.sh"
    exit 0
fi

echo ""

# Check proxies
echo -e "${BLUE}Proxy Ports:${NC}"
if nc -z 127.0.0.1 8889 2>/dev/null; then
    echo -e "  SOCKS5 (8889): ${GREEN}listening${NC}"
else
    echo -e "  SOCKS5 (8889): ${RED}not responding${NC}"
fi

if nc -z 127.0.0.1 8888 2>/dev/null; then
    echo -e "  HTTP   (8888): ${GREEN}listening${NC}"
else
    echo -e "  HTTP   (8888): ${RED}not responding${NC}"
fi

echo ""

# Test PMACS connectivity
echo -e "${BLUE}PMACS Connectivity:${NC}"
if command -v curl &> /dev/null; then
    if curl -s --connect-timeout 3 --proxy socks5h://127.0.0.1:8889 http://prometheus.pmacs.upenn.edu &> /dev/null; then
        echo -e "  ${GREEN}Reachable${NC}"
    else
        echo -e "  ${YELLOW}Cannot verify (may still work)${NC}"
    fi
else
    echo -e "  ${YELLOW}curl not available for testing${NC}"
fi

echo ""
