#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this remover as root." >&2
  exit 1
fi

systemctl disable --now gamepath-relay.service 2>/dev/null || true
rm -f /etc/systemd/system/gamepath-relay.service
systemctl daemon-reload
systemctl reset-failed gamepath-relay.service 2>/dev/null || true

nft list table inet gamepath_filter >/dev/null 2>&1 && nft delete table inet gamepath_filter || true
nft list table ip gamepath_nat >/dev/null 2>&1 && nft delete table ip gamepath_nat || true
rm -f /etc/nftables.d/gamepath.nft

ip link delete gptun0 2>/dev/null || true
rm -f /usr/local/bin/gamepath-relay
rm -rf /etc/gamepath /var/lib/gamepath /var/cache/gamepath
rm -f /etc/sysctl.d/90-gamepath-relay.conf
sysctl --system >/dev/null 2>&1 || true
userdel gamepath 2>/dev/null || true

echo "GamePath relay removed."
