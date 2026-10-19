#!/usr/bin/env bash
# usage: spike/run-hold.sh <variant> [hold flags...]
# Runs spike/out/<variant>/relay and the hold load generator in one Linux container.
set -euo pipefail
cd "$(dirname "$0")"
variant="$1"
shift
mkdir -p out/results
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o out/hold ./hold
docker run --rm --cpus 4 -e SPIKE_HANDOFF -e SPIKE_PINGTIMER -e SPIKE_READBUF -e SPIKE_MODE -e SPIKE_TAG \
  --sysctl net.ipv4.ip_local_port_range="1024 65535" \
  --ulimit nofile=1048576:1048576 \
  -v "$PWD/out:/w" alpine:3.22 sh -c '
    variant="$1"; shift
    out="/w/results/$variant${SPIKE_TAG:+-$SPIKE_TAG}"; mkdir -p $out
    env RELAY_ADDR=127.0.0.1:8080 RELAY_PRIVATE_ADDR=127.0.0.1:9090 \
      RELAY_ADMISSION_RATE=1000000 RELAY_MAX_CONNS_PER_IP=1000000 GOMEMLIMIT=2GiB \
      /w/$variant/relay >/dev/null 2>$out/relay.log &
    pid=$!
    until wget -qO- http://127.0.0.1:9090/healthz >/dev/null 2>&1; do sleep 0.1; done
    /w/hold -pid $pid -profiles $out "$@"
    kill $pid; wait $pid || true
  ' sh "$variant" "$@"
