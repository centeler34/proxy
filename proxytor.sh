#!/bin/bash
set -euo pipefail

# —————————

# Tor + WireGuard Server Setup

# Listens on UDP 51820 and forces all WireGuard client traffic through Tor

# —————————

# Colors for output

GREEN=”\e[32m”
YELLOW=”\e[33m”
RED=”\e[31m”
NC=”\e[0m”

cleanup() {
echo -e “${YELLOW}Cleaning up partial changes…${NC}”
systemctl stop wg-quick@wg0.service || true
systemctl stop tor.service || true
}
trap cleanup ERR

# Re-run with sudo if not root

if [ “$EUID” -ne 0 ]; then
echo “Re-running script with sudo…”
exec sudo bash “$0” “$@”
fi

echo -e “${GREEN}Starting Tor+WireGuard server setup…${NC}”

# Detect distribution

if [ -f /etc/arch-release ]; then
PKG_INSTALL=“pacman -Sy –noconfirm”
else
echo -e “${YELLOW}Warning: script was written for Arch Linux (uses pacman).${NC}”
echo -e “${YELLOW}Please install tor, wireguard-tools and iptables manually if using another distro.${NC}”
PKG_INSTALL=“true”
fi

# Install packages (Arch)

if [ “$PKG_INSTALL” != “true” ]; then
echo -e “${GREEN}Installing required packages…${NC}”
$PKG_INSTALL tor wireguard-tools iptables
fi

# Directories and files

WG_CONF_DIR=”/etc/wireguard”
WG_CONF_FILE=”${WG_CONF_DIR}/wg0.conf”
WG_PRIVATE_KEY_FILE=”${WG_CONF_DIR}/server_private.key”
WG_PUBLIC_KEY_FILE=”${WG_CONF_DIR}/server_public.key”
TORRC=”/etc/tor/torrc”
BACKUP_TS=$(date +%s)
mkdir -p “${WG_CONF_DIR}”

# WireGuard settings

WG_LISTEN_PORT=51820
WG_NETWORK=“10.10.0.0/24”
WG_SERVER_ADDR=“10.10.0.1/24”

# Tor settings (transparent proxy)

TOR_TRANS_PORT=9040
TOR_DNS_PORT=5353
TOR_VIRTUAL_NETWORK=“10.192.0.0/10”

# Find external interface (the interface used to reach the internet)

EXT_IF=$(ip route get 1.1.1.1 2>/dev/null | grep -oP ‘dev \K\S+’ | head -n1)
if [ -z “${EXT_IF}” ]; then
# fallback
EXT_IF=$(ip route | awk ‘/default/ {print $5; exit}’)
fi
if [ -z “${EXT_IF}” ]; then
echo -e “${RED}Could not detect external interface. Exiting.${NC}”
exit 1
fi
echo -e “${GREEN}Detected external interface: ${EXT_IF}${NC}”

# Generate WireGuard server key pair (if not already present)

if [ ! -f “${WG_PRIVATE_KEY_FILE}” ]; then
umask 077
wg genkey | tee “${WG_PRIVATE_KEY_FILE}” | wg pubkey > “${WG_PUBLIC_KEY_FILE}”
chmod 600 “${WG_PRIVATE_KEY_FILE}” “${WG_PUBLIC_KEY_FILE}”
echo -e “${GREEN}Generated WireGuard server keypair.${NC}”
else
echo -e “${YELLOW}Server private key exists, reusing.${NC}”
fi

SERVER_PRIVATE_KEY=$(cat “${WG_PRIVATE_KEY_FILE}”)
SERVER_PUBLIC_KEY=$(cat “${WG_PUBLIC_KEY_FILE}”)

# Create WireGuard server config

cat > “${WG_CONF_FILE}.new” <<EOF
[Interface]
Address = ${WG_SERVER_ADDR}
ListenPort = ${WG_LISTEN_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
SaveConfig = true
EOF

mv “${WG_CONF_FILE}.new” “${WG_CONF_FILE}”
chmod 600 “${WG_CONF_FILE}”
echo -e “${GREEN}Wrote WireGuard config to ${WG_CONF_FILE}${NC}”

# Enable IP forwarding

sysctl -w net.ipv4.ip_forward=1
if ! grep -q “net.ipv4.ip_forward” /etc/sysctl.conf 2>/dev/null; then
echo “net.ipv4.ip_forward = 1” >> /etc/sysctl.conf
fi

# Configure Tor for transparent proxying

if [ -f “${TORRC}” ]; then
cp “${TORRC}” “${TORRC}.bak.${BACKUP_TS}”
echo -e “${YELLOW}Backed up existing ${TORRC} to ${TORRC}.bak.${BACKUP_TS}${NC}”
fi

cat > “${TORRC}” <<EOF
RunAsDaemon 1
VirtualAddrNetworkIPv4 ${TOR_VIRTUAL_NETWORK}
AutomapHostsOnResolve 1
TransPort ${TOR_TRANS_PORT}
DNSPort ${TOR_DNS_PORT}
EOF

echo -e “${GREEN}Wrote tor configuration to ${TORRC}${NC}”

# Configure iptables

echo -e “${GREEN}Applying iptables rules…${NC}”

# Flush existing custom rules

iptables -t nat -D PREROUTING -i wg0 -p tcp -j REDIRECT –to-ports ${TOR_TRANS_PORT} 2>/dev/null || true
iptables -t nat -D PREROUTING -i wg0 -p udp –dport 53 -j REDIRECT –to-ports ${TOR_DNS_PORT} 2>/dev/null || true
iptables -t nat -D PREROUTING -i wg0 -p tcp –dport 53 -j REDIRECT –to-ports ${TOR_DNS_PORT} 2>/dev/null || true
iptables -t nat -D POSTROUTING -o ${EXT_IF} -j MASQUERADE 2>/dev/null || true

iptables -D INPUT -p udp –dport ${WG_LISTEN_PORT} -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true

# Allow WireGuard port from anywhere (UDP)

iptables -A INPUT -p udp –dport ${WG_LISTEN_PORT} -j ACCEPT

# Allow established, related

iptables -A INPUT -m conntrack –ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow forwarding for wg0

iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT

# NAT/MASQ

iptables -t nat -A POSTROUTING -o ${EXT_IF} -j MASQUERADE

# Redirect TCP from wg0 to Tor TransPort

iptables -t nat -A PREROUTING -i wg0 -p tcp -j REDIRECT –to-ports ${TOR_TRANS_PORT}

# Redirect DNS (udp/tcp port 53) from wg0 to Tor’s DNSPort

iptables -t nat -A PREROUTING -i wg0 -p udp –dport 53 -j REDIRECT –to-ports ${TOR_DNS_PORT}
iptables -t nat -A PREROUTING -i wg0 -p tcp –dport 53 -j REDIRECT –to-ports ${TOR_DNS_PORT}

echo -e “${GREEN}iptables rules applied.${NC}”

# Persist iptables rules

if command -v iptables-save >/dev/null 2>&1; then
mkdir -p /etc/iptables
iptables-save > /etc/iptables/iptables.rules
if command -v systemctl >/dev/null 2>&1; then
systemctl enable iptables 2>/dev/null || true
systemctl start iptables 2>/dev/null || true
fi
fi

# Enable and start Tor

echo -e “${GREEN}Enabling and starting Tor…${NC}”
systemctl enable tor.service
systemctl restart tor.service

# Wait for Tor to come up

sleep 2

# Enable and start WireGuard

echo -e “${GREEN}Bringing up wg0 interface…${NC}”
systemctl enable wg-quick@wg0.service
systemctl restart wg-quick@wg0.service

echo -e “${GREEN}Setup complete.${NC}”
echo -e “${YELLOW}IMPORTANT:${NC} If this machine is behind a NAT router, forward UDP ${WG_LISTEN_PORT} to this machine’s LAN IP.”
echo -e “${YELLOW}If machine has a public IP, ensure your provider allows incoming UDP on ${WG_LISTEN_PORT}.${NC}”

# Print server info

PUBLIC_IP=$(curl -s https://ifconfig.me 2>/dev/null || echo ‘YOUR_PUBLIC_IP’)
echo
echo -e “${GREEN}WireGuard server public key:${NC} ${SERVER_PUBLIC_KEY}”
echo -e “${GREEN}Server listen port:${NC} ${WG_LISTEN_PORT}”
echo -e “${GREEN}Server public IP (detected):${NC} ${PUBLIC_IP}”
echo
echo “==== Sample client configuration ====”
echo “[Interface]”
echo “PrivateKey = <CLIENT_PRIVATE_KEY>”
echo “Address = 10.10.0.2/24”
echo “DNS = 10.10.0.1”
echo “”
echo “[Peer]”
echo “PublicKey = ${SERVER_PUBLIC_KEY}”
echo “Endpoint = ${PUBLIC_IP}:${WG_LISTEN_PORT}”
echo “AllowedIPs = 0.0.0.0/0, ::/0”
echo “PersistentKeepalive = 25”
echo
echo -e “${GREEN}All done. Clients that connect will have TCP and DNS traffic redirected through Tor.${NC}”
