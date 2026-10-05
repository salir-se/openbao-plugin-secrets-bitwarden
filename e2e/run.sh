#!/usr/bin/env bash
# End-to-end test: builds the environment in e2e/compose.yaml, loads the plugin
# from this checkout into a real OpenBao, drives it with the `bao` CLI and
# checks the outcome with the Bitwarden CLI. The cases are in
# e2e/scripts/suite.sh and run inside the tools container, so the host needs
# Docker with Compose v2 and nothing else.
#
#   ./e2e/run.sh          # build, start, test, tear down
#   KEEP=1 ./e2e/run.sh   # leave the environment running afterwards
#
# Ports: E2E_OPENBAO_PORT (28200) and E2E_VAULTWARDEN_PORT (28443), both on
# 127.0.0.1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/compose.yaml" --profile tools)
KEEP="${KEEP:-0}"

info() { printf '[e2e] %s\n' "$*"; }

# shellcheck disable=SC2329 # invoked through the EXIT trap below
finish() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    info "FAILED (exit code $rc). Container logs follow."
    "${COMPOSE[@]}" logs --no-color --tail=300 || true
  fi
  if [ "$KEEP" = "1" ]; then
    info "KEEP=1: environment left running. Remove it with: mise run e2e-down"
  else
    info "Tearing down..."
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap finish EXIT

started=$SECONDS

info "Removing any previous run..."
"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true

info "Building images (plugin from this checkout)..."
"${COMPOSE[@]}" build --quiet

info "Starting OpenBao and Vaultwarden, running setup..."
"${COMPOSE[@]}" run --rm setup

info "Running the suite..."
"${COMPOSE[@]}" run --rm --no-deps -T tools /e2e/suite.sh

info "Finished in $((SECONDS - started))s"
