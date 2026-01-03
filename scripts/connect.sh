#!/usr/bin/env bash
# PMACS Utils - Connect to VPN
# Starts OpenConnect with split tunneling via vpn-slice

set -e

# TODO: Implement
# 1. Load username from ~/.config/pmacs/config
# 2. Run openconnect with vpn-slice:
#    sudo openconnect psomvpn.uphs.upenn.edu \
#      --protocol=gp \
#      --user=$PMACS_USER \
#      -s 'vpn-slice prometheus.pmacs.upenn.edu'
# 3. User enters password, then "push" for DUO
# 4. Wait for connection, report status

echo "Connect not yet implemented. Run on macOS to develop."
