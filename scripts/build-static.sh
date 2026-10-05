#!/usr/bin/env bash
# Build a static plugin binary for one platform into dist/ and, for Linux,
# verify that the result is statically linked.
#
# Usage: scripts/build-static.sh <goos> <goarch>
# Example: scripts/build-static.sh linux arm64
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <goos> <goarch>" >&2
  exit 2
fi

goos="$1"
goarch="$2"
out="dist/openbao-plugin-secrets-bitwarden_${goos}_${goarch}"

CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
  go build -trimpath -ldflags='-s -w' -o "$out" ./cmd/openbao-plugin-secrets-bitwarden
echo "built $out"

if [ "$goos" = linux ]; then
  info="$(file "$out")"
  echo "$info"
  if ! grep -q 'statically linked' <<<"$info"; then
    echo "FAIL: $out is not statically linked" >&2
    exit 1
  fi
fi
