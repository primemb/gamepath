#!/usr/bin/env bash
set -Eeuo pipefail

PORT=51821
BIND_ADDRESS="0.0.0.0"
CLIENT_NAME="windows-client"
ENROLLMENT_OUTPUT="/root/gamepath-${CLIENT_NAME}.enroll"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_TOOLCHAIN="1.85.0"

usage() {
  cat <<'EOF'
Install or update a GamePath relay on Debian 13+ or Ubuntu 22.04+.

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

if [[ ! -r /etc/os-release ]]; then
  echo "Could not identify this Linux distribution (/etc/os-release is missing)." >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  debian)
    if ! dpkg --compare-versions "${VERSION_ID:-0}" ge 13; then
      echo "Unsupported Debian release: ${PRETTY_NAME:-Debian ${VERSION_ID:-unknown}}. Debian 13 or newer is required." >&2
      exit 1
    fi
    USE_RUSTUP=0
    ;;
  ubuntu)
    if ! dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04; then
      echo "Unsupported Ubuntu release: ${PRETTY_NAME:-Ubuntu ${VERSION_ID:-unknown}}. Ubuntu 22.04 or newer is required." >&2
      exit 1
    fi
    # Ubuntu LTS repositories can ship a compiler older than the Rust 2024
    # edition required by the relay. Keep a pinned toolchain isolated here.
    USE_RUSTUP=1
    ;;
  *)
    echo "Unsupported Linux distribution: ${PRETTY_NAME:-${ID:-unknown}}. Use Debian 13+ or Ubuntu 22.04+." >&2
    exit 1
    ;;
esac

export DEBIAN_FRONTEND=noninteractive
echo "GAMEPATH_PROGRESS:dependencies"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl nftables iproute2 build-essential pkg-config

if (( USE_RUSTUP == 1 )); then
  export RUSTUP_HOME=/var/cache/gamepath/rustup
  export CARGO_HOME=/var/cache/gamepath/cargo
  install -d -m 0755 "$RUSTUP_HOME" "$CARGO_HOME"
  RUSTUP_INIT="$(mktemp)"
  trap 'rm -f "$RUSTUP_INIT"' EXIT
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    https://sh.rustup.rs -o "$RUSTUP_INIT"
  sh "$RUSTUP_INIT" -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --no-modify-path
  rm -f "$RUSTUP_INIT"
  trap - EXIT
  CARGO="$CARGO_HOME/bin/cargo"
else
  # Debian 13 ships Rust 1.85, the minimum compiler accepted by the relay.
  apt-get install -y --no-install-recommends cargo rustc
  CARGO=cargo
fi

if ! id gamepath >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/gamepath --create-home --shell /usr/sbin/nologin gamepath
fi
install -d -m 0750 -o root -g gamepath /etc/gamepath /etc/gamepath/clients
install -d -m 0755 -o gamepath -g gamepath /var/lib/gamepath

install -d -m 0755 /var/cache/gamepath/cargo-target
export CARGO_TARGET_DIR=/var/cache/gamepath/cargo-target
echo "GAMEPATH_PROGRESS:compile"
"$CARGO" build --release --locked --manifest-path "$REPO_ROOT/relay/Cargo.toml"
install -m 0755 "$CARGO_TARGET_DIR/release/gamepath-relay" /usr/local/bin/gamepath-relay

echo "GAMEPATH_PROGRESS:network"
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
    # The tunnel resolver below answers on 10.203.0.1 only. An open resolver on
    # a public address is a DNS amplification reflector, so the uplink is
    # refused explicitly rather than left to dnsmasq's own binding.
    iifname "${UPLINK_INTERFACE}" udp dport 53 drop
    iifname "${UPLINK_INTERFACE}" tcp dport 53 drop
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

# A resolver inside the tunnel.
#
# Without one, Windows has no nameserver on its tunnel adapter and falls back to
# the physical adapter's — the user's home router — so every name lookup leaves
# outside the tunnel no matter how much traffic goes through it. That is a
# privacy leak, and on a filtered connection it is worse than that: a poisoned
# answer sends a game to a dead or wrong address while the tunnel itself is
# perfectly healthy. Resolving here also means names resolve from the relay's
# location, so a CDN or game service hands back a node near the exit rather than
# one near the user's ISP.
#
# The client probes this before using it and falls back to a public resolver
# through the tunnel, so a relay without dnsmasq still works — it just resolves
# further away.
if apt-get install -y --no-install-recommends dnsmasq; then
  # Debian's package starts a system-wide resolver on 0.0.0.0:53. Everything
  # below narrows it to the tunnel: `bind-dynamic` because gptun0 does not
  # exist until the relay runs and must be picked up when it appears, and
  # `no-resolv` because /etc/resolv.conf on a systemd-resolved host points at a
  # stub this would then forward to in a circle.
  cat >/etc/dnsmasq.d/gamepath.conf <<'EOF'
interface=gptun0
listen-address=10.203.0.1
bind-dynamic
no-dhcp-interface=gptun0
no-resolv
no-hosts
domain-needed
bogus-priv
cache-size=1000
server=8.8.8.8
server=1.1.1.1
EOF
  systemctl enable dnsmasq.service >/dev/null 2>&1 || true
  systemctl restart dnsmasq.service || true
  if systemctl is-active --quiet dnsmasq.service; then
    echo "Tunnel resolver active on 10.203.0.1"
  else
    echo "WARNING: dnsmasq did not start; clients will resolve through a public resolver." >&2
  fi
else
  echo "WARNING: dnsmasq could not be installed; clients will resolve through a public resolver." >&2
fi

# Docker installs a later FORWARD base chain whose policy is drop. An accept in
# our earlier base chain therefore is not enough: Docker evaluates afterwards
# and rejects packets from gptun0. DOCKER-USER is Docker's supported hook for
# administrator forwarding rules. The service repeats this setup at boot after
# Docker has created the chain, while these rules fix an already-running host.
if nft list chain ip filter DOCKER-USER >/dev/null 2>&1; then
  if ! nft list chain ip filter DOCKER-USER | grep -Fq 'gamepath relay outbound'; then
    nft insert rule ip filter DOCKER-USER iifname "gptun0" oifname "${UPLINK_INTERFACE}" \
      ip saddr 10.203.0.0/24 \
      accept comment '"gamepath relay outbound"'
  fi
  if ! nft list chain ip filter DOCKER-USER | grep -Fq 'gamepath relay return'; then
    nft insert rule ip filter DOCKER-USER iifname "${UPLINK_INTERFACE}" oifname "gptun0" \
      ip daddr 10.203.0.0/24 \
      ct state established,related accept comment '"gamepath relay return"'
  fi
fi

cat >/usr/local/lib/gamepath-relay-allow-docker-forward <<'EOF'
#!/bin/sh
set -eu

UPLINK_INTERFACE="$1"
if ! nft list chain ip filter DOCKER-USER >/dev/null 2>&1; then
  exit 0
fi
if ! nft list chain ip filter DOCKER-USER | grep -Fq 'gamepath relay outbound'; then
  nft insert rule ip filter DOCKER-USER iifname "gptun0" oifname "$UPLINK_INTERFACE" \
    ip saddr 10.203.0.0/24 \
    accept comment '"gamepath relay outbound"'
fi
if ! nft list chain ip filter DOCKER-USER | grep -Fq 'gamepath relay return'; then
  nft insert rule ip filter DOCKER-USER iifname "$UPLINK_INTERFACE" oifname "gptun0" \
    ip daddr 10.203.0.0/24 \
    ct state established,related accept comment '"gamepath relay return"'
fi
EOF
chmod 0755 /usr/local/lib/gamepath-relay-allow-docker-forward

echo "GAMEPATH_PROGRESS:service"
cat >/etc/gamepath/relay.env <<EOF
GAMEPATH_BIND=${BIND_ADDRESS}:${PORT}
GAMEPATH_CLIENTS=/etc/gamepath/clients
GAMEPATH_UPLINK=${UPLINK_INTERFACE}
EOF
chmod 0640 /etc/gamepath/relay.env
chown root:gamepath /etc/gamepath/relay.env

cat >/etc/systemd/system/gamepath-relay.service <<'EOF'
[Unit]
Description=GamePath authenticated multipath relay
After=network-online.target nftables.service docker.service
Wants=network-online.target

[Service]
Type=simple
User=gamepath
Group=gamepath
EnvironmentFile=/etc/gamepath/relay.env
ExecStartPre=+/usr/local/lib/gamepath-relay-allow-docker-forward ${GAMEPATH_UPLINK}
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
  echo "GAMEPATH_PROGRESS:enrollment"
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
