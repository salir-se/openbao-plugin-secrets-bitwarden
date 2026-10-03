#!/usr/bin/env bash
# Runs the build-tagged integration tests against throwaway OpenBao and
# Vaultwarden containers (docker-compose.test.yml). Requires docker, curl, go.
#
# Ports default to 18200 (OpenBao) and 18080 (Vaultwarden) on localhost and
# can be changed with TEST_OPENBAO_PORT / TEST_VAULTWARDEN_PORT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.test.yml"

export TEST_OPENBAO_PORT="${TEST_OPENBAO_PORT:-18200}"
export TEST_VAULTWARDEN_PORT="${TEST_VAULTWARDEN_PORT:-18080}"
BAO_URL="http://127.0.0.1:${TEST_OPENBAO_PORT}"
VW_URL="http://127.0.0.1:${TEST_VAULTWARDEN_PORT}"
ROOT_TOKEN="test-root-token"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { printf "${YELLOW}[TEST]${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
fail()  { printf "${RED}[FAIL]${NC} %s\n" "$1"; }

# shellcheck disable=SC2329 # invoked through the EXIT trap below
cleanup() {
  info "Tearing down test containers..."
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ============================================================================
# Step 1: Start test infrastructure
# ============================================================================
info "Starting test infrastructure (OpenBao + Vaultwarden)..."
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f "$COMPOSE_FILE" up -d

info "Waiting for services to be healthy..."
for i in $(seq 1 30); do
  if curl -sf -o /dev/null "$BAO_URL/v1/sys/health" && curl -sf -o /dev/null "$VW_URL/alive"; then
    ok "Both services healthy"
    break
  fi
  if [ "$i" -eq 30 ]; then
    fail "Services did not become healthy in time"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
  fi
  sleep 2
done

# ============================================================================
# Step 2: Seed OpenBao with test secrets
# ============================================================================
info "Seeding OpenBao with test data..."

# The dev server already mounts KV v2 at secret/; ignore "path is already in use".
curl -s -o /dev/null -X POST "$BAO_URL/v1/sys/mounts/secret" \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"kv","options":{"version":"2"}}' || true

curl -sf -o /dev/null -X POST "$BAO_URL/v1/secret/data/test-service" \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"testuser","password":"testpass123","url":"https://test.example.com"}}'

curl -sf -o /dev/null -X POST "$BAO_URL/v1/secret/data/test-db" \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"dbadmin","password":"dbpass456","url":"postgresql://localhost:5432/testdb"}}'

ok "OpenBao seeded with test secrets"

# ============================================================================
# Step 3: Run integration tests
# ============================================================================
# The Vaultwarden test account is registered by the Go tests themselves
# (testhelpers_test.go), so no Bitwarden CLI is needed.
info "Running Go integration tests..."
cd "$PROJECT_DIR"

export TEST_OPENBAO_ADDR="$BAO_URL"
export TEST_OPENBAO_TOKEN="$ROOT_TOKEN"
export TEST_VAULTWARDEN_URL="$VW_URL"
export TEST_VAULTWARDEN_EMAIL="test@example.com"
export TEST_VAULTWARDEN_PASSWORD="TestPassword123!"

TEST_EXIT=0
go test -v -tags integration -count=1 -timeout 300s -run 'Integration' ./... || TEST_EXIT=$?

if [ "$TEST_EXIT" -eq 0 ]; then
  ok "All integration tests passed"
else
  fail "Integration tests failed (exit code: $TEST_EXIT)"
fi

exit "$TEST_EXIT"
