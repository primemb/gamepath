#!/usr/bin/env bash
set -Eeuo pipefail

PORT=51821
BIND_ADDRESS="0.0.0.0"
CLIENT_NAME="windows-client"
ENROLLMENT_OUTPUT="/root/gamepath-${CLIENT_NAME}.enroll"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Install or update a GamePath relay on Debian 13.

Usage: sudo bash deploy/install-relay.sh [options]
  --port NUMBER                 UDP listen port (default: 51821)
  --bind ADDRESS               Listen address (default: 0.0.0.0)
  --client-name NAME           Enroll this client if none exists
  --enrollment-output PATH     Root-readable token output path
  --no-enroll                  Do not create an initial client

The script is idempotent: run it again after pulling new code to update the
binary and service without replacing existing client credentials.
EOF
}

DO_ENROLL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --bind) BIND_ADDRESS="$2"; shift 2 ;;
    --client-name) CLIENT_NAME="$2"; shift 2 ;;
    --enrollment-output) ENROLLMENT_OUTPUT="$2"; shift 2 ;;
    --no-enroll) DO_ENROLL=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "Invalid UDP port: $PORT" >&2
  exit 1
fi
if [[ ! -f "$REPO_ROOT/relay/Cargo.toml" || ! -f "$REPO_ROOT/engine/Cargo.toml" ]]; then
  echo "Run this script from a complete GamePath repository checkout." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates cargo rustc nftables iproute2 build-essential pkg-config

if ! id gamepath >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/gamepath --create-home --shell /usr/sbin/nologin gamepath
fi
install -d -m 0750 -o root -g gamepath /etc/gamepath /etc/gamepath/clients
install -d -m 0755 -o gamepath -g gamepath /var/lib/gamepath

install -d -m 0755 /var/cache/gamepath/cargo-target
export CARGO_TARGET_DIR=/var/cache/gamepath/cargo-target
cargo build --release --manifest-path "$REPO_ROOT/relay/Cargo.toml"
install -m 0755 "$CARGO_TARGET_DIR/release/gamepath-relay" /usr/local/bin/gamepath-relay

cat >/etc/sysctl.d/90-gamepath-relay.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sysctl --system >/dev/null

UPLINK_INTERFACE="$(ip -4 route show default | awk 'NR == 1 { print $5 }')"
if [[ -z "$UPLINK_INTERFACE" ]]; then
  echo "Could not determine the public uplink interface." >&2
  exit 1
fi

install -d -m 0755 /etc/nftables.d
cat >/etc/nftables.d/gamepath.nft <<EOF
table inet gamepath_filter {
  chain input {
    type filter hook input priority -10; policy accept;
    udp dport ${PORT} accept
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "gptun0" oifname "${UPLINK_INTERFACE}" accept
    iifname "${UPLINK_INTERFACE}" oifname "gptun0" ct state established,related accept
  }
}
table ip gamepath_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.203.0.0/24 oifname "${UPLINK_INTERFACE}" masquerade
  }
}
EOF
touch /etc/nftables.conf
if ! grep -Fq 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf; then
  printf '\ninclude "/etc/nftables.d/*.nft"\n' >>/etc/nftables.conf
fi
nft list table inet gamepath_filter >/dev/null 2>&1 && nft delete table inet gamepath_filter || true
nft list table ip gamepath_nat >/dev/null 2>&1 && nft delete table ip gamepath_nat || true
nft -f /etc/nftables.d/gamepath.nft
systemctl enable nftables.service >/dev/null

cat >/etc/gamepath/relay.env <<EOF
GAMEPATH_BIND=${BIND_ADDRESS}:${PORT}
GAMEPATH_CLIENTS=/etc/gamepath/clients
EOF
chmod 0640 /etc/gamepath/relay.env
chown root:gamepath /etc/gamepath/relay.env

cat >/etc/systemd/system/gamepath-relay.service <<'EOF'
[Unit]
Description=GamePath authenticated multipath relay
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
User=gamepath
Group=gamepath
EnvironmentFile=/etc/gamepath/relay.env
ExecStart=/usr/local/bin/gamepath-relay serve --bind ${GAMEPATH_BIND} --clients-dir ${GAMEPATH_CLIENTS} --tun-name gptun0 --tun-address 10.203.0.1 --tun-prefix 24
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

if (( DO_ENROLL == 1 )) && [[ ! -f "$ENROLLMENT_OUTPUT" ]]; then
  umask 077
  /usr/local/bin/gamepath-relay enroll \
    --name "$CLIENT_NAME" \
    --clients-dir /etc/gamepath/clients \
    --output "$ENROLLMENT_OUTPUT"
  chown root:root "$ENROLLMENT_OUTPUT"
  chmod 0600 "$ENROLLMENT_OUTPUT"
fi

chmod 0640 /etc/gamepath/clients/*.json 2>/dev/null || true
chown root:gamepath /etc/gamepath/clients/*.json 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now gamepath-relay.service
systemctl restart gamepath-relay.service

echo
echo "GamePath relay installed."
echo "  UDP endpoint: ${BIND_ADDRESS}:${PORT}"
echo "  Public interface: ${UPLINK_INTERFACE}"
echo "  Service: systemctl status gamepath-relay"
if [[ -f "$ENROLLMENT_OUTPUT" ]]; then
  echo "  Enrollment token file: ${ENROLLMENT_OUTPUT} (mode 0600)"
fi
