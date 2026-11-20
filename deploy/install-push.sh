#!/usr/bin/env bash
set -euo pipefail
dir=${1:?usage: install-push.sh <private staging directory>}
sudo install -m 0755 "$dir/push" /usr/local/bin/supaterm-push
sudo install -m 0644 "$dir/supaterm-push.service" /etc/systemd/system/supaterm-push.service
rm -r -- "$dir"
sudo systemctl daemon-reload
sudo systemctl restart supaterm-push.service
for _ in $(seq 40); do
  if curl -fsS localhost:8000/healthz; then
    sudo systemctl enable supaterm-push.service
    exit 0
  fi
  sleep 0.5
done
sudo journalctl -u supaterm-push -n 50 --no-pager
exit 1
