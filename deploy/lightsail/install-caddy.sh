#!/usr/bin/env bash
set -euo pipefail
hostname=$1
if ! command -v caddy >/dev/null; then
  for _ in $(seq 300); do
    [ -e /var/lib/cloud/instance/boot-finished ] && break
    sleep 1
  done
  sudo apt-get -o DPkg::Lock::Timeout=300 update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y caddy
fi
caddyfile=$(mktemp)
printf '%s {\n\treverse_proxy 127.0.0.1:8080\n}\n' "$hostname" > "$caddyfile"
if ! cmp -s "$caddyfile" /etc/caddy/Caddyfile; then
  sudo install -m 0644 "$caddyfile" /etc/caddy/Caddyfile
  sudo systemctl reload-or-restart caddy
fi
rm "$caddyfile"
