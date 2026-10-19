#!/usr/bin/env bash
# usage: spike/run-epoll.sh <goroutine|epoll> [load flags...]
set -euo pipefail
cd "$(dirname "$0")"
mode="$1"
shift
mkdir -p out/epoll
(cd epoll && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o ../out/epoll/server ./server && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/epoll/load ./load)
docker run --rm --cpus 4 \
  --sysctl net.ipv4.ip_local_port_range="1024 65535" \
  --ulimit nofile=1048576:1048576 \
  -v "$PWD/out:/w" alpine:3.22 sh -c '
    mode="$1"; shift
    GOMEMLIMIT=2GiB /w/epoll/server -mode "$mode" >/dev/null 2>/w/epoll/server-$mode.log &
    pid=$!
    until wget -qO- http://127.0.0.1:8080/stats >/dev/null 2>&1; do sleep 0.1; done
    /w/epoll/load -pid $pid "$@"
    kill $pid; wait $pid || true
  ' sh "$mode" "$@"
