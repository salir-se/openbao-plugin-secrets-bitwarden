#!/usr/bin/env bash
# Configures the e2e environment. Runs in the tools image as the one-shot
# `setup` service, after OpenBao and Vaultwarden are healthy. Idempotent.
set -euo pipefail

PLUGIN=openbao-plugin-secrets-bitwarden
MOUNT=bitwarden
POLICY=bitwarden-e2e-sync-read
STATE_FILE=/state/e2e.env

log() { printf '[setup] %s\n' "$*"; }

if [ -s "$STATE_FILE" ] && bao read "$MOUNT/config" >/dev/null 2>&1; then
  log "already configured, nothing to do"
  exit 0
fi

# --- Vaultwarden ------------------------------------------------------------
# Three accounts, one organization, the collections and the memberships.
log "Vaultwarden: accounts, organization, collections, memberships"
bootstrap="$(e2e-bootstrap)"
printf '%s\n' "$bootstrap"

primary="${E2E_VW_COLLECTIONS%%,*}"
secondary="${E2E_VW_COLLECTIONS#*,}"
org_id="$(jq -er '.organization_id' <<<"$bootstrap")"
collection_id="$(jq -er --arg n "$primary" '.collections[$n]' <<<"$bootstrap")"
secondary_id="$(jq -er --arg n "$secondary" '.collections[$n]' <<<"$bootstrap")"

# --- OpenBao: plugin ----------------------------------------------------------
# The binary is already in plugin_directory (e2e/openbao.Dockerfile). Register
# it by SHA-256 and mount it, as in the README.
log "OpenBao: register and mount the plugin"
bao plugin register -sha256="$(cat /state/plugin.sha256)" secret "$PLUGIN"
if ! bao secrets list -format=json | jq -e --arg m "$MOUNT/" 'has($m)' >/dev/null; then
  bao secrets enable -path="$MOUNT" "$PLUGIN"
fi

# --- OpenBao: source secrets --------------------------------------------------
# The dev server mounts KV v2 at secret/. Seed only what is missing, so that
# re-running setup never undoes a manual rotation.
log "OpenBao: seed KV secrets under secret/shared/"
seed() {
  local path="$1"
  shift
  bao kv get "$path" >/dev/null 2>&1 || bao kv put "$path" "$@" >/dev/null
}
seed secret/shared/grafana \
  username=admin password=grafana-initial-password url=https://grafana.example.com
seed secret/shared/postgres \
  username=app password=postgres-initial-password url=postgresql://db.example.com:5432/app \
  host=db.example.com port=5432
seed secret/shared/api-keys \
  primary=e2e-fixture-key-1 secondary=e2e-fixture-key-2
# Outside the policy below: the plugin must not be able to read it.
seed secret/not-synced/payroll \
  username=payroll password=must-never-reach-bitwarden

# --- OpenBao: token for the plugin --------------------------------------------
# Read-only, limited to the paths that are synced. Not the root token.
log "OpenBao: scoped read-only token for the plugin"
bao policy write "$POLICY" - >/dev/null <<'POLICY'
path "secret/data/shared/*" {
  capabilities = ["read"]
}
POLICY
sync_token="$(bao token create -orphan -policy="$POLICY" -period=24h \
  -display-name=bitwarden-e2e-sync -field=token)"

# --- OpenBao: connect the plugin ----------------------------------------------
# https:// to Vaultwarden (private CA, trusted through the system trust store
# of the OpenBao container) and http:// to OpenBao over the compose network.
log "OpenBao: write $MOUNT/config"
bao write "$MOUNT/config" \
  url="$E2E_VW_URL" \
  email="$E2E_SYNC_EMAIL" \
  password="$E2E_SYNC_PASSWORD" \
  organization_id="$org_id" \
  bao_addr="$BAO_ADDR" \
  bao_token="$sync_token" >/dev/null

status="$(bao read -format=json "$MOUNT/status")"
jq '.data' <<<"$status"
jq -e '.data.ok == true' <<<"$status" >/dev/null || {
  log "plugin status is not ok"
  exit 1
}

cat >"$STATE_FILE.tmp" <<STATE
E2E_ORG_ID=$org_id
E2E_COLLECTION_ID=$collection_id
E2E_COLLECTION_SECONDARY_ID=$secondary_id
STATE
mv "$STATE_FILE.tmp" "$STATE_FILE"

log "done: organization $org_id, collection $collection_id"
