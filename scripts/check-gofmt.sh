#!/usr/bin/env bash
# Fail when Go files are not gofmt-formatted, printing the files and the diff.
#
# Usage: scripts/check-gofmt.sh [file-or-dir ...]   (default: the whole tree)
set -euo pipefail

paths=("$@")
if [ "${#paths[@]}" -eq 0 ]; then
  paths=(.)
fi

unformatted="$(gofmt -l "${paths[@]}")"
if [ -n "$unformatted" ]; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::These files are not gofmt-formatted:"
  else
    echo "These files are not gofmt-formatted:" >&2
  fi
  echo "$unformatted"
  gofmt -d "${paths[@]}"
  exit 1
fi

echo "OK: gofmt-formatted"
