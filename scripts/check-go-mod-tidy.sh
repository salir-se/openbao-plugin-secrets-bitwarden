#!/usr/bin/env bash
# Fail when `go mod tidy` would change go.mod or go.sum. Note that it runs
# `go mod tidy`, so a failure leaves the tidied files in the working tree.
#
# Usage: scripts/check-go-mod-tidy.sh
set -euo pipefail

go mod tidy
if ! git diff --exit-code -- go.mod go.sum; then
  echo "go.mod or go.sum is not tidy: run 'go mod tidy' and commit the result" >&2
  exit 1
fi

echo "OK: go.mod and go.sum are tidy"
