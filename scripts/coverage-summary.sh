#!/usr/bin/env bash
# Print a Markdown per-function coverage report for a Go cover profile.
# CI appends it to the job summary; locally it just prints.
#
# Usage: scripts/coverage-summary.sh [profile]   (default: coverage.out)
set -euo pipefail

profile="${1:-coverage.out}"

if [ ! -s "$profile" ]; then
  echo "coverage profile '$profile' is missing or empty" >&2
  exit 2
fi

echo '### Coverage'
echo '```'
go tool cover -func="$profile"
echo '```'
