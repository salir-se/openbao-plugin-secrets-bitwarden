#!/usr/bin/env bash
# Example: configure the plugin and declare a few roles in one idempotent run.
#
# Role definitions live in the plugin's storage, so they are lost when the
# mount is disabled. Keeping them in a script like this one makes the setup
# repeatable. Copy it, replace the example roles with your own, and run it
# whenever the mount is (re)created or a role changes.
#
# Required environment:
#   BAO_ADDR          OpenBao API address used by the `bao` CLI
#   BAO_TOKEN         token allowed to write to the plugin mount
#   BW_URL            Bitwarden-compatible server URL (tested with Vaultwarden)
#   BW_EMAIL          service account email
#   BW_PASSWORD       service account master password (account must use PBKDF2)
#   PLUGIN_BAO_TOKEN  token the plugin uses to read the source KV secrets;
#                     give it a read-only policy limited to those paths
#
# Optional environment:
#   BW_ORG_ID         organization UUID; unset syncs to the personal vault
#   BW_COLLECTION_ID  collection UUID for the example roles (organization only)
#   PLUGIN_BAO_ADDR   address the plugin uses to reach OpenBao (default: BAO_ADDR)
#   MOUNT             plugin mount path (default: bitwarden)
#   SYNC_INTERVAL     periodic sync interval, e.g. 10m (default: disabled)
#
# Usage:
#   BAO_ADDR=https://bao.example.com BAO_TOKEN=... BW_URL=https://vault.example.com \
#   BW_EMAIL=sync@example.com BW_PASSWORD=... PLUGIN_BAO_TOKEN=... ./setup-roles.sh
set -euo pipefail

for var in BAO_ADDR BAO_TOKEN BW_URL BW_EMAIL BW_PASSWORD PLUGIN_BAO_TOKEN; do
  if [ -z "${!var:-}" ]; then
    echo "missing required environment variable: $var" >&2
    exit 1
  fi
done
export BAO_ADDR BAO_TOKEN

MOUNT="${MOUNT:-bitwarden}"
PLUGIN_BAO_ADDR="${PLUGIN_BAO_ADDR:-$BAO_ADDR}"

# ---------------------------------------------------------------------------
# 1. Connection settings
# ---------------------------------------------------------------------------
config_args=(
  url="$BW_URL"
  email="$BW_EMAIL"
  password="$BW_PASSWORD"
  bao_addr="$PLUGIN_BAO_ADDR"
  bao_token="$PLUGIN_BAO_TOKEN"
)
if [ -n "${BW_ORG_ID:-}" ]; then
  config_args+=(organization_id="$BW_ORG_ID")
fi
if [ -n "${SYNC_INTERVAL:-}" ]; then
  config_args+=(sync_interval="$SYNC_INTERVAL")
fi

bao write "$MOUNT/config" "${config_args[@]}"
echo "configured $MOUNT/config"

# ---------------------------------------------------------------------------
# 2. Roles: one per vault item
# ---------------------------------------------------------------------------
# role <name> <field=value>...  — creates or updates a role.
role() {
  local name="$1"; shift
  local args=("$@")
  if [ -n "${BW_ORG_ID:-}" ] && [ -n "${BW_COLLECTION_ID:-}" ]; then
    args+=(collection_ids="$BW_COLLECTION_ID")
  fi
  bao write "$MOUNT/roles/$name" "${args[@]}"
  echo "role: $name"
}

# Login item (cipher_type=1). The *_field options name keys of the KV secret.
# KV v2 paths include "data/": the secret written with
#   bao kv put secret/grafana username=admin password=... url=https://grafana.example.com
# is read from "secret/data/grafana".
role grafana \
  source_path="secret/data/grafana" \
  cipher_name="Grafana" \
  cipher_type=1 \
  user_field="username" \
  pass_field="password" \
  url_field="url" \
  extra_urls="https://metrics.example.com"

# Login item without a username, with a note shown in the vault.
role api-gateway \
  source_path="secret/data/api-gateway" \
  cipher_name="API Gateway token" \
  cipher_type=1 \
  pass_field="token" \
  notes_template="Managed by OpenBao. Do not edit here; changes are overwritten on the next sync."

# Secure note (cipher_type=2): every key of the secret becomes a custom field.
role deploy-keys \
  source_path="secret/data/deploy-keys" \
  cipher_name="Deploy keys" \
  cipher_type=2

# ---------------------------------------------------------------------------
# 3. Push everything once and show the result
# ---------------------------------------------------------------------------
bao write -f "$MOUNT/sync"
bao list "$MOUNT/sync"
