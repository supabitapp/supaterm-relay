#!/usr/bin/env bash
set -euo pipefail
if ! command -v caddy >/dev/null; then
  for _ in $(seq 300); do
    [ -e /var/lib/cloud/instance/boot-finished ] && break
    sleep 1
  done
  sudo apt-get -o DPkg::Lock::Timeout=300 update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y caddy
fi
printf '%s {\n\treverse_proxy 127.0.0.1:8080\n}\n' "$1" | sudo tee /etc/caddy/Caddyfile >/dev/null
sudo systemctl start caddy
sudo caddy reload --config /etc/caddy/Caddyfile
