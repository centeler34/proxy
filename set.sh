#!/bin/bash
set -euo pipefail

GREEN=”\e[32m”
YELLOW=”\e[33m”
RED=”\e[31m”
NC=”\e[0m”

# Re-run with sudo if not root

if [ “${EUID}” -ne 0 ]; then
echo “Re-running with sudo…”
exec sudo bash “${0}” “${@}”
fi

echo -e “${YELLOW}Stopping Tor + WireGuard proxy services…${NC}”

# Stop WireGuard

echo -e “${GREEN}Stopping WireGuard…${NC}”
systemctl stop wg-quick@wg0.service 2>/dev/null || echo “WireGuard not running”
systemctl disable wg-quick@wg0.service 2>/dev/null || true

# Stop Tor

echo -e “${GREEN}Stopping Tor…${NC}”
systemctl stop tor.service 2>/dev/null || echo “Tor not running”
systemctl disable tor.service 2>/dev/null || true

# Flush iptables rules

echo -e “${GREEN}Flushing iptables rules…${NC}”
iptables -t nat -F 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true

# Set default policies to ACCEPT

iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Remove saved iptables rules

if [ -f /etc/iptables/iptables.rules ]; then
echo -e “${GREEN}Removing saved iptables rules…${NC}”
rm -f /etc/iptables/iptables.rules
fi

# Disable IP forwarding

echo -e “${GREEN}Disabling IP forwarding…${NC}”
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sed -i ‘/net.ipv4.ip_forward/d’ /etc/sysctl.conf 2>/dev/null || true

echo
echo -e “${GREEN}=== ALL SERVICES STOPPED ===${NC}”
echo -e “${YELLOW}WireGuard and Tor have been stopped and disabled${NC}”
echo -e “${YELLOW}Firewall rules have been flushed${NC}”
echo -e “${YELLOW}IP forwarding has been disabled${NC}”
echo
echo -e “To completely remove configs, run:”
echo -e “  ${GREEN}sudo rm -rf /etc/wireguard/*${NC}”
echo -e “  ${GREEN}sudo rm /etc/tor/torrc.backup${NC}”
