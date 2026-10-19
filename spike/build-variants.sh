#!/usr/bin/env bash
# Builds spike/out/baseline/relay from this checkout and spike/out/lean/relay with lean.patch applied.
set -euo pipefail
cd "$(dirname "$0")/.."
build() { (cd "$1" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags spike -trimpath -o "$2" ./cmd/relay); }
mkdir -p spike/out/baseline spike/out/lean
build . "$PWD/spike/out/baseline/relay"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp -R go.mod go.sum cmd internal "$tmp/"
(cd "$tmp" && patch -s -p1 < "$OLDPWD/spike/lean.patch")
build "$tmp" "$PWD/spike/out/lean/relay"
