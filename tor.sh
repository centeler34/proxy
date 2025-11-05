#!/bin/bash
set -euo pipefail

GREEN=”\e[32m”
YELLOW=”\e[33m”
RED=”\e[31m”
NC=”\e[0m”

cleanup() {
echo -e “${YELLOW}Cleaning up…${NC}”
systemctl stop wg-quick@wg0.service 2>/dev/null || true
systemctl stop tor.service 2>/dev/null || true
}
trap cleanup ERR

if [ “${EUID}” -ne 0 ]; then
echo “Re-running with sudo…”
exec sudo bash “${0}” “${@}”
fi

echo -e “${GREEN}Starting Tor+WireGuard setup…${NC}”

# Install packages

if [ -f /etc/arch-release ]; then
pacman -Sy –noconfirm tor wireguard-tools iptables
elif [ -f /etc/debian_version ]; then
apt-get update && apt-get install -y tor wireguard iptables
else
echo -e “${RED}Unsupported distro. Install tor, wireguard-tools, iptables manually.${NC}”
exit 1
fi

# Config variables

WG_DIR=”/etc/wireguard”
WG_CONF=”${WG_DIR}/wg0.conf”
WG_PRIVKEY=”${WG_DIR}/server_private.key”
WG_PUBKEY=”${WG_DIR}/server_public.key”
WG_PORT=51820
WG_NET=“10.10.0.0/24”
WG_ADDR=“10.10.0.1/24”

TOR_TRANS=9040
TOR_DNS=5353
TORRC=”/etc/tor/torrc”

mkdir -p “${WG_DIR}”

# Get external interface

EXT_IF=$(ip route | grep default | head -n1 | awk ‘{print $5}’)
if [ -z “${EXT_IF}” ]; then
echo -e “${RED}Cannot detect external interface${NC}”
exit 1
fi
echo -e “${GREEN}External interface: ${EXT_IF}${NC}”

# Generate WireGuard keys

if [ ! -f “${WG_PRIVKEY}” ]; then
umask 077
wg genkey | tee “${WG_PRIVKEY}” | wg pubkey > “${WG_PUBKEY}”
chmod 600 “${WG_PRIVKEY}” “${WG_PUBKEY}”
echo -e “${GREEN}Generated WireGuard keys${NC}”
fi

PRIVKEY=$(cat “${WG_PRIVKEY}”)
PUBKEY=$(cat “${WG_PUBKEY}”)

# Create WireGuard config

cat > “${WG_CONF}” <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${PRIVKEY}
SaveConfig = true
EOF

chmod 600 “${WG_CONF}”

# Enable IP forwarding

sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q “net.ipv4.ip_forward” /etc/sysctl.conf 2>/dev/null || echo “net.ipv4.ip_forward = 1” >> /etc/sysctl.conf

# Configure Tor

[ -f “${TORRC}” ] && cp “${TORRC}” “${TORRC}.backup”

cat > “${TORRC}” <<EOF
RunAsDaemon 1
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort ${TOR_TRANS}
DNSPort ${TOR_DNS}
EOF

echo -e “${GREEN}Configured Tor${NC}”

# Setup iptables

echo -e “${GREEN}Configuring firewall…${NC}”

# Clean old rules

iptables -t nat -F 2>/dev/null || true
iptables -F 2>/dev/null || true

# Allow WireGuard

iptables -A INPUT -p udp –dport ${WG_PORT} -j ACCEPT
iptables -A INPUT -m conntrack –ctstate RELATED,ESTABLISHED -j ACCEPT

# Forward wg0

iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT

# NAT

iptables -t nat -A POSTROUTING -o ${EXT_IF} -j MASQUERADE

# Redirect to Tor

iptables -t nat -A PREROUTING -i wg0 -p tcp -j REDIRECT –to-ports ${TOR_TRANS}
iptables -t nat -A PREROUTING -i wg0 -p udp –dport 53 -j REDIRECT –to-ports ${TOR_DNS}
iptables -t nat -A PREROUTING -i wg0 -p tcp –dport 53 -j REDIRECT –to-ports ${TOR_DNS}

# Save iptables

mkdir -p /etc/iptables
iptables-save > /etc/iptables/iptables.rules
systemctl enable iptables 2>/dev/null || true

# Start services

echo -e “${GREEN}Starting services…${NC}”
systemctl enable tor.service
systemctl restart tor.service
sleep 2

systemctl enable wg-quick@wg0.service
systemctl restart wg-quick@wg0.service

# Get public IP

PUBIP=$(curl -s https://ifconfig.me 2>/dev/null || echo “YOUR_PUBLIC_IP”)

echo
echo -e “${GREEN}=== SETUP COMPLETE ===${NC}”
echo -e “Server Public Key: ${PUBKEY}”
echo -e “Server Port: ${WG_PORT}”
echo -e “Server IP: ${PUBIP}”
echo
echo “=== CLIENT CONFIG ===”
echo “[Interface]”
echo “PrivateKey = CLIENT_PRIVATE_KEY_HERE”
echo “Address = 10.10.0.2/24”
echo “DNS = 10.10.0.1”
echo
echo “[Peer]”
echo “PublicKey = ${PUBKEY}”
echo “Endpoint = ${PUBIP}:${WG_PORT}”
echo “AllowedIPs = 0.0.0.0/0”
echo “PersistentKeepalive = 25”
echo
echo -e “${GREEN}Done! Generate client keys with: wg genkey | tee privatekey | wg pubkey${NC}”
