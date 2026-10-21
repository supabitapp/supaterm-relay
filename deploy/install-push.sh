#!/usr/bin/env bash
set -euo pipefail
sudo install -m 0755 /tmp/push /usr/local/bin/supaterm-push
sudo install -m 0644 /tmp/supaterm-push.service /etc/systemd/system/supaterm-push.service
rm /tmp/push /tmp/supaterm-push.service
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
