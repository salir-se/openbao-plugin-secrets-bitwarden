#!/usr/bin/env bash
# Fail when total statement coverage in a Go cover profile is below a threshold.
#
# Usage: scripts/check-coverage.sh <profile> <threshold-percent>
# Example: scripts/check-coverage.sh coverage.out 95.0
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <profile> <threshold-percent>" >&2
  exit 2
fi

profile="$1"
threshold="$2"

if [ ! -s "$profile" ]; then
  echo "coverage profile '$profile' is missing or empty" >&2
  exit 2
fi
if ! [[ "$threshold" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "threshold '$threshold' is not a number" >&2
  exit 2
fi

report="$(go tool cover -func="$profile")"
echo "$report"

total="$(awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }' <<<"$report")"
if [ -z "$total" ]; then
  echo "could not find the total line in the coverage report" >&2
  exit 2
fi

if awk -v t="$total" -v min="$threshold" 'BEGIN { exit !(t + 0 < min + 0) }'; then
  echo "FAIL: total coverage ${total}% is below the required ${threshold}%" >&2
  exit 1
fi

echo "OK: total coverage ${total}% (required: ${threshold}%)"
