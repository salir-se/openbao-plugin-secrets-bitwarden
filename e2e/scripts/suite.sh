#!/usr/bin/env bash
# End-to-end cases. Runs inside the tools container (started by e2e/run.sh)
# against the environment that e2e/scripts/setup.sh configured.
#
# Every case drives the real plugin through the `bao` CLI and checks the result
# independently through the Bitwarden CLI, logged in as a different account
# than the one the plugin uses: the Developer, who has read-only access to the
# collection.
#
# Result lines:
#   PASS   the case passed
#   FAIL   the case failed; its output follows
#   KNOWN  the case pins the current behaviour of a known defect. It turns
#          into FAIL when that behaviour changes, so that the suite and the
#          documentation are updated together with the fix.
set -euo pipefail

MOUNT=bitwarden
PERSONAL_MOUNT=bitwarden-personal
PLUGIN=openbao-plugin-secrets-bitwarden
KV=secret/shared
# OpenBao drives periodic sync from its own background tick (about once a
# minute in 2.5.1), so the wait has to be longer than that.
PERIODIC_TIMEOUT="${E2E_PERIODIC_TIMEOUT:-240}"

pass=0
failed=0
known=0
failed_names=()

# --- helpers ------------------------------------------------------------------

die() {
  printf 'assertion failed: %s\n' "$*" >&2
  exit 1
}

# eq <actual> <expected> <what>
eq() {
  [ "$1" = "$2" ] || die "$3: got '$1', want '$2'"
}

# json_ok <json> <jq filter> <what>: the filter must yield true.
json_ok() {
  jq -e "$2" >/dev/null <<<"$1" || die "$3 (jq: $2) in: $(jq -c . <<<"$1" 2>/dev/null || printf '%s' "$1")"
}

# expect_fail <what> <command...>: the command must exit non-zero. Its combined
# output is left in $out.
expect_fail() {
  local what="$1"
  shift
  if out="$("$@" 2>&1)"; then
    die "$what: command succeeded, expected it to fail. Output: $out"
  fi
}

# as <admin|sync|developer>: log the Bitwarden CLI in as that account. Called
# between cases, because a case runs in a subshell.
as() {
  BW_SESSION="$(bw-session.sh "$1")"
  export BW_SESSION
  printf -- '--- Bitwarden CLI logged in as %s\n' "$1"
}

# vault_item <id>: the item as the logged-in account sees it on the server.
vault_item() {
  bw sync >/dev/null
  bw get item "$1"
}

# vault_lacks <id>: the logged-in account cannot see the item.
vault_lacks() {
  bw sync >/dev/null
  if bw get item "$1" >/dev/null 2>&1; then
    die "item $1 is still visible in the vault"
  fi
}

role_cipher_id() {
  bao read -field=cipher_id "$MOUNT/roles/$1"
}

# run <name> <function>: run one case in a subshell with errexit on.
run() {
  run_case PASS "$@"
}

# known <reference> <name> <function>: the function asserts the defective
# behaviour as it is today.
known() {
  local ref="$1"
  shift
  run_case "KNOWN" "$1 [$ref]" "$2"
}

run_case() {
  local label="$1" name="$2" fn="$3" log rc started=$SECONDS
  log="$(mktemp)"
  set +e
  (
    set -euo pipefail
    "$fn"
  ) >"$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    printf '%-5s  %s (%ss)\n' "$label" "$name" "$((SECONDS - started))"
    if [ "$label" = "KNOWN" ]; then known=$((known + 1)); else pass=$((pass + 1)); fi
  else
    printf 'FAIL   %s (%ss)\n' "$name" "$((SECONDS - started))"
    if [ "$label" = "KNOWN" ]; then
      echo "       This case pins a known defect and no longer sees it. If the defect"
      echo "       is fixed, turn the case into a normal one and update the docs."
    fi
    sed 's/^/       | /' "$log"
    failed=$((failed + 1))
    failed_names+=("$name")
  fi
  rm -f "$log"
}

# --- cases: the plugin inside a real OpenBao ----------------------------------

case_plugin_registered() {
  local info mount sha
  sha="$(cat /state/plugin.sha256)"
  info="$(bao plugin info -format=json secret "$PLUGIN")"
  json_ok "$info" '.builtin == false' "plugin is external"
  eq "$(jq -r '.sha256' <<<"$info")" "$sha" "registered SHA-256"
  mount="$(bao secrets list -format=json | jq --arg m "$MOUNT/" '.[$m]')"
  eq "$(jq -r '.type' <<<"$mount")" "$PLUGIN" "mount type"
  eq "$(jq -r '.running_sha256' <<<"$mount")" "$sha" "SHA-256 of the running plugin"
}

case_status_ok() {
  local status
  status="$(bao read -format=json "$MOUNT/status" | jq '.data')"
  json_ok "$status" '.configured == true' "configured"
  json_ok "$status" '.vaultwarden_reachable == true' "reachable"
  json_ok "$status" '.authenticated == true' "authenticated"
  json_ok "$status" '.ok == true' "ok"
}

case_config_redacted() {
  local raw
  raw="$(bao read -format=json "$MOUNT/config")"
  eq "$(jq -c '.data | keys' <<<"$raw")" \
    '["bao_addr","bao_tls_skip_verify","email","organization_id","sync_interval","url"]' \
    "fields returned by config read"
  eq "$(jq -r '.data.email' <<<"$raw")" "$E2E_SYNC_EMAIL" "email"
  eq "$(jq -r '.data.organization_id' <<<"$raw")" "$E2E_ORG_ID" "organization_id"
  if grep -qF "$E2E_SYNC_PASSWORD" <<<"$raw"; then
    die "config read returned the master password"
  fi
  # The same through the table output a person would look at.
  if bao read "$MOUNT/config" | grep -Eq '^(password|bao_token) '; then
    die "config read lists password or bao_token"
  fi
}

case_tls() {
  local cfg handshake
  cfg="$(bao read -format=json "$MOUNT/config" | jq '.data')"
  # Plugin -> Vaultwarden: https. The plugin has no CA option and no way to
  # skip verification for this connection, so an "ok" status (checked above)
  # means Go verified the certificate against the container's trust store.
  json_ok "$cfg" '.url | startswith("https://")' "plugin talks https to the vault"
  # Plugin -> OpenBao: plain http over the compose network, by service name.
  json_ok "$cfg" '.bao_addr == "http://openbao:8200"' "bao_addr"

  # The certificate verifies against the private CA...
  handshake="$(openssl s_client -connect vaultwarden:443 -servername vaultwarden \
    -no-CApath -CAfile /state/ca.crt -verify_return_error </dev/null 2>&1)" ||
    die "TLS handshake with the private CA failed: $handshake"
  grep -q 'Verify return code: 0 (ok)' <<<"$handshake" || die "certificate not verified: $handshake"
  grep -q 'issuer=.*Throwaway e2e CA' <<<"$handshake" || die "unexpected issuer: $handshake"
  # ...and against nothing else: with public roots only, verification fails.
  # This is what the plugin would hit if the CA were not installed.
  if openssl s_client -connect vaultwarden:443 -servername vaultwarden \
    -no-CApath -CAfile /usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt \
    -verify_return_error </dev/null >/dev/null 2>&1; then
    die "the certificate verified without the private CA"
  fi
}

# --- cases: the sharing model -------------------------------------------------

# Needs: as admin.
case_three_identities() {
  local members
  bw sync >/dev/null
  members="$(bw list org-members --organizationid "$E2E_ORG_ID")"
  # type: 0 owner, 1 admin, 2 user. status 2: confirmed.
  json_ok "$members" 'length == 3' "three members"
  eq "$(jq -r --arg e "$E2E_ADMIN_EMAIL" '.[] | select(.email == $e) | "\(.type)/\(.status)"' <<<"$members")" \
    "0/2" "Admin is a confirmed owner"
  eq "$(jq -r --arg e "$E2E_DEVELOPER_EMAIL" '.[] | select(.email == $e) | "\(.type)/\(.status)"' <<<"$members")" \
    "2/2" "Developer is a confirmed user"
  local want_type
  case "$E2E_SYNC_MEMBER_TYPE" in
    owner) want_type=0 ;;
    admin) want_type=1 ;;
    manager) want_type=3 ;;
    *) want_type=2 ;;
  esac
  eq "$(jq -r --arg e "$E2E_SYNC_EMAIL" '.[] | select(.email == $e) | "\(.type)/\(.status)"' <<<"$members")" \
    "$want_type/2" "sync account role ($E2E_SYNC_MEMBER_TYPE)"
}

# Needs: as developer.
case_share() {
  local out id item listed
  bao kv put "$KV/suite-grafana" \
    username=grafana-admin password=initial-password-1 \
    url=https://grafana.example.com environment=staging >/dev/null
  bao write "$MOUNT/roles/suite-grafana" \
    source_path="secret/data/shared/suite-grafana" \
    cipher_name="Suite Grafana" \
    user_field=username pass_field=password url_field=url \
    collection_ids="$E2E_COLLECTION_ID" \
    notes_template="Managed by OpenBao. Edits here are overwritten." >/dev/null

  out="$(bao write -format=json -f "$MOUNT/sync/suite-grafana" | jq '.data')"
  id="$(jq -r '.cipher_id' <<<"$out")"
  [ -n "$id" ] && [ "$id" != "null" ] || die "sync returned no cipher_id: $out"
  eq "$(role_cipher_id suite-grafana)" "$id" "cipher_id stored on the role"

  # The Developer, with their own account and master password, sees it.
  item="$(vault_item "$id")"
  eq "$(jq -r '.name' <<<"$item")" "Suite Grafana" "item name"
  eq "$(jq -r '.type' <<<"$item")" "1" "item type (login)"
  eq "$(jq -r '.login.username' <<<"$item")" "grafana-admin" "username"
  eq "$(jq -r '.login.password' <<<"$item")" "initial-password-1" "password"
  eq "$(jq -c '[.login.uris[].uri]' <<<"$item")" '["https://grafana.example.com"]' "URIs"
  eq "$(jq -r '.notes' <<<"$item")" "Managed by OpenBao. Edits here are overwritten." "notes"
  eq "$(jq -r '.organizationId' <<<"$item")" "$E2E_ORG_ID" "organization"
  eq "$(jq -c '.collectionIds' <<<"$item")" "[\"$E2E_COLLECTION_ID\"]" "collections"

  listed="$(bw list items --collectionid "$E2E_COLLECTION_ID")"
  json_ok "$listed" "any(.[]; .id == \"$id\")" "item is listed in the shared collection"
}

case_custom_fields() {
  local item
  item="$(vault_item "$(role_cipher_id suite-grafana)")"
  # `environment` is not claimed by a *_field option, so it becomes a
  # plain-text (type 0) custom field. Mapped keys do not.
  eq "$(jq -c '[.fields[] | {name, value, type}]' <<<"$item")" \
    '[{"name":"environment","value":"staging","type":0}]' "custom fields"
}

case_rotate() {
  local before after item
  before="$(role_cipher_id suite-grafana)"
  bao kv patch "$KV/suite-grafana" password=rotated-password-2 >/dev/null
  bao write -f "$MOUNT/sync/suite-grafana" >/dev/null
  after="$(role_cipher_id suite-grafana)"
  eq "$after" "$before" "item ID after rotation"

  item="$(vault_item "$before")"
  eq "$(jq -r '.login.password' <<<"$item")" "rotated-password-2" "password the Developer sees"
  eq "$(jq -r '.login.username' <<<"$item")" "grafana-admin" "username is untouched"
  # One item, not a second copy next to the old one.
  eq "$(bw list items --organizationid "$E2E_ORG_ID" | jq '[.[] | select(.name == "Suite Grafana")] | length')" \
    "1" "number of items named Suite Grafana"
}

case_developer_read_only() {
  local id item template
  id="$(role_cipher_id suite-grafana)"

  # An edit does not reach the server. (bw 2026.2.0 exits 0 here and prints
  # the unchanged item, so the check is the value after a fresh sync.)
  bw get item "$id" | jq '.login.password = "changed-by-developer"' | bw encode |
    bw edit item "$id" >/dev/null 2>&1 || true
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.password' <<<"$item")" "rotated-password-2" "password after the Developer's edit attempt"

  expect_fail "Developer deletes the item" bw delete item "$id"
  item="$(vault_item "$id")"
  eq "$(jq -r '.id' <<<"$item")" "$id" "item still exists"

  template="$(bw get template item | jq --arg o "$E2E_ORG_ID" --arg c "$E2E_COLLECTION_ID" \
    '.name = "Created by developer" | .organizationId = $o | .collectionIds = [$c]
     | .login = {username: "x", password: "y"}' | bw encode)"
  expect_fail "Developer creates an item in the collection" bw create item "$template"
}

case_inventory() {
  local roles state status
  roles="$(bao list -detailed -format=json "$MOUNT/roles" | jq '.data')"
  json_ok "$roles" '.keys | index("suite-grafana") != null' "role is listed"
  json_ok "$roles" '.key_info["suite-grafana"].synced == true' "role is marked synced"
  json_ok "$roles" '.key_info["suite-grafana"].source_path == "secret/data/shared/suite-grafana"' "source path"

  state="$(bao read -format=json "$MOUNT/sync/suite-grafana" | jq '.data')"
  json_ok "$state" '.synced == true' "sync state"
  json_ok "$state" '.cipher_name == "Suite Grafana"' "cipher name"
  json_ok "$state" '(.synced_at | length) > 0' "synced_at"
  json_ok "$state" '(.revision_date | length) > 0' "revision_date fetched from the vault"
  json_ok "$state" 'has("vaultwarden_error") | not' "no vault error"

  status="$(bao read -format=json "$MOUNT/status" | jq '.data')"
  json_ok "$status" '.total_roles >= 1 and .synced_roles >= 1' "role counters"
}

case_sync_all() {
  local out item note
  bao kv put "$KV/suite-postgres" \
    username=app password=postgres-password-1 url=postgresql://db.example.com:5432/app >/dev/null
  bao kv put "$KV/suite-api-keys" primary=fixture-key-1 secondary=fixture-key-2 >/dev/null
  bao write "$MOUNT/roles/suite-postgres" \
    source_path="secret/data/shared/suite-postgres" cipher_name="Suite Postgres" \
    user_field=username pass_field=password url_field=url \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null
  bao write "$MOUNT/roles/suite-api-keys" \
    source_path="secret/data/shared/suite-api-keys" cipher_name="Suite API keys" cipher_type=2 \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null

  out="$(bao write -format=json -f "$MOUNT/sync" | jq '.data')"
  json_ok "$out" '.total == 3 and .synced == 3 and .failed == 0' "sync-all counters"
  json_ok "$out" '[.results[] | .status] | all(. == "synced")' "per-role results"

  item="$(vault_item "$(role_cipher_id suite-postgres)")"
  eq "$(jq -r '.login.password' <<<"$item")" "postgres-password-1" "postgres password"

  # A secure note carries every key of the secret as a custom field.
  note="$(bw get item "$(role_cipher_id suite-api-keys)")"
  eq "$(jq -r '.type' <<<"$note")" "2" "item type (secure note)"
  eq "$(jq -c '[.fields[] | {name, value}] | sort_by(.name)' <<<"$note")" \
    '[{"name":"primary","value":"fixture-key-1"},{"name":"secondary","value":"fixture-key-2"}]' \
    "secure note fields"
}

case_scoped_token() {
  # setup.sh seeded secret/not-synced/payroll, outside the policy of the
  # plugin's bao_token. The caller here holds the root token, and still the
  # read is refused: source reads use bao_token, not the caller's token.
  bao write "$MOUNT/roles/suite-outside" \
    source_path="secret/data/not-synced/payroll" cipher_name="Suite Payroll" \
    user_field=username pass_field=password \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null
  expect_fail "sync of a path outside the token's policy" bao write -f "$MOUNT/sync/suite-outside"
  grep -q 'permission denied' <<<"$out" || die "expected 'permission denied', got: $out"
  eq "$(role_cipher_id suite-outside)" "" "no item was created"
  bw sync >/dev/null
  eq "$(bw list items --organizationid "$E2E_ORG_ID" | jq '[.[] | select(.name == "Suite Payroll")] | length')" \
    "0" "items named Suite Payroll"
  bao delete "$MOUNT/roles/suite-outside" >/dev/null
}

case_periodic() {
  local id deadline password=""
  id="$(role_cipher_id suite-grafana)"
  bao write "$MOUNT/config" sync_interval=5s >/dev/null
  bao kv patch "$KV/suite-grafana" password=periodic-password-3 >/dev/null

  # No `bao write sync/...` from here on.
  deadline=$((SECONDS + PERIODIC_TIMEOUT))
  while [ "$SECONDS" -lt "$deadline" ]; do
    password="$(vault_item "$id" | jq -r '.login.password')"
    [ "$password" = "periodic-password-3" ] && break
    sleep 5
  done
  eq "$password" "periodic-password-3" "password after waiting ${PERIODIC_TIMEOUT}s for a periodic run"
  eq "$(role_cipher_id suite-grafana)" "$id" "item ID after the periodic run"
  json_ok "$(bao read -format=json "$MOUNT/status" | jq '.data')" \
    '(.last_periodic_sync | length) > 0' "status reports the periodic run"

  # Switch it off again so that later cases are driven by manual syncs only.
  bao write "$MOUNT/config" sync_interval="" >/dev/null
  eq "$(bao read -field=sync_interval "$MOUNT/config")" "" "sync_interval cleared"
}

# Needs: as admin.
case_manual_edit_overwritten() {
  local id item
  id="$(role_cipher_id suite-grafana)"
  bw sync >/dev/null
  bw get item "$id" | jq '.login.password = "edited-in-the-vault"' | bw encode |
    bw edit item "$id" >/dev/null
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.password' <<<"$item")" "edited-in-the-vault" "the Admin's manual edit took effect"

  bao write -f "$MOUNT/sync/suite-grafana" >/dev/null
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.password' <<<"$item")" "periodic-password-3" "password after the next sync"
}

# --- cases: the playbooks of docs/way-of-working.md ------------------------------
# These run with the tokens the playbooks hand out, not with the root token:
#   bitwarden-admin    the Admin's policy on the plugin mount
#   developer-intake   write-only access to the shared KV prefix
#   ci-acme-api        one pipeline: its own KV path and its own sync path

# with_token <token> <command...>
with_token() {
  local token="$1"
  shift
  BAO_TOKEN="$token" "$@"
}

token_for() {
  bao token create -orphan -policy="$1" -ttl=30m -field=token
}

playbook_policies() {
  bao policy write bitwarden-admin - >/dev/null <<'POLICY'
path "bitwarden/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
POLICY
  bao policy write developer-intake - >/dev/null <<'POLICY'
path "secret/data/shared/*" {
  capabilities = ["create", "update"]
}
POLICY
}

# Scenario 1. Needs: as developer.
case_wow_new_shared_account() {
  local admin dev id item
  playbook_policies
  admin="$(token_for bitwarden-admin)"
  dev="$(token_for developer-intake)"

  # Developer: hands the new credential to OpenBao. Write-only: `bao kv put`
  # needs create/update on the data path and nothing else.
  with_token "$dev" bao kv put "$KV/social-acme" \
    username=acme-social password=social-password-1 url=https://social.example.com >/dev/null
  expect_fail "Developer reads the KV secret back" with_token "$dev" bao kv get "$KV/social-acme"
  expect_fail "Developer lists the KV prefix" with_token "$dev" bao kv list "$KV"
  expect_fail "Developer writes outside the intake prefix" with_token "$dev" bao kv put secret/elsewhere/x a=b
  expect_fail "Developer creates a role" with_token "$dev" bao write "$MOUNT/roles/social-acme" \
    source_path="secret/data/shared/social-acme" cipher_name="Acme social"
  expect_fail "Developer reads the plugin config" with_token "$dev" bao read "$MOUNT/config"
  expect_fail "Developer triggers a sync" with_token "$dev" bao write -f "$MOUNT/sync/suite-grafana"

  # Admin: applies the reviewed role definition and syncs. The Admin policy
  # covers the mount only, not the KV data.
  with_token "$admin" bao write "$MOUNT/roles/social-acme" \
    source_path="secret/data/shared/social-acme" cipher_name="Acme social" \
    user_field=username pass_field=password url_field=url \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null
  with_token "$admin" bao write -f "$MOUNT/sync/social-acme" >/dev/null
  expect_fail "Admin policy reads KV data" with_token "$admin" bao kv get "$KV/social-acme"

  # Every Developer with access to the collection now has it.
  id="$(role_cipher_id social-acme)"
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.username' <<<"$item")" "acme-social" "username"
  eq "$(jq -r '.login.password' <<<"$item")" "social-password-1" "password"
  eq "$(jq -c '.collectionIds' <<<"$item")" "[\"$E2E_COLLECTION_ID\"]" "collections"
}

# Scenario 2.
case_wow_manual_rotation() {
  local admin dev id item
  admin="$(token_for bitwarden-admin)"
  dev="$(token_for developer-intake)"
  id="$(role_cipher_id social-acme)"

  # The person who changed the password at the vendor writes the new value to
  # the same path. A write-only token has to send the whole secret:
  # `bao kv patch` needs the `patch` capability, or read + update.
  expect_fail "bao kv patch with a create/update-only token" \
    with_token "$dev" bao kv patch "$KV/social-acme" password=social-password-2
  with_token "$dev" bao kv put "$KV/social-acme" \
    username=acme-social password=social-password-2 url=https://social.example.com >/dev/null

  with_token "$admin" bao write -f "$MOUNT/sync/social-acme" >/dev/null
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.password' <<<"$item")" "social-password-2" "password after the members' next sync"
  eq "$(role_cipher_id social-acme)" "$id" "item ID"
}

# Scenario 3.
case_wow_compromise() {
  local admin id state item
  admin="$(token_for bitwarden-admin)"
  id="$(role_cipher_id social-acme)"

  # After the credential was changed at the target system: new value into KV,
  # forced sync, confirmation.
  bao kv put "$KV/social-acme" \
    username=acme-social password=social-password-3-after-incident url=https://social.example.com >/dev/null
  with_token "$admin" bao write -f "$MOUNT/sync/social-acme" >/dev/null
  state="$(with_token "$admin" bao read -format=json "$MOUNT/sync/social-acme" | jq '.data')"
  json_ok "$state" '.synced == true and (.revision_date | length) > 0' "sync state after the forced sync"
  json_ok "$(with_token "$admin" bao read -format=json "$MOUNT/status" | jq '.data')" '.ok == true' "status"

  item="$(vault_item "$id")"
  eq "$(jq -r '.login.password' <<<"$item")" "social-password-3-after-incident" "password the Developer sees"

  # KV v2 keeps the compromised versions (1 and 2 here) until destroyed.
  bao kv destroy -versions=1,2 "$KV/social-acme" >/dev/null
  json_ok "$(bao kv metadata get -format=json "$KV/social-acme")" \
    '.data.versions["1"].destroyed and .data.versions["2"].destroyed and (.data.versions["3"].destroyed | not)' \
    "old versions destroyed, current one kept"
  eq "$(bao kv get -field=password "$KV/social-acme")" "social-password-3-after-incident" "current KV value"
}

# Scenario 5.
case_wow_cicd_placeholder() {
  local admin ci role_id secret_id id item generated out

  # Admin (apply step after the pull request is merged): placeholder value,
  # role, and a pipeline identity that can fill this one secret and trigger
  # this one sync.
  admin="$(token_for bitwarden-admin)"
  bao kv put "$KV/ci-acme-api" \
    status="pending - will be filled by the acme-provision pipeline" >/dev/null
  with_token "$admin" bao write "$MOUNT/roles/ci-acme-api" \
    source_path="secret/data/shared/ci-acme-api" cipher_name="Acme API key (CI)" \
    user_field=username pass_field=password url_field=url \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null
  with_token "$admin" bao write -f "$MOUNT/sync/ci-acme-api" >/dev/null

  cat >/tmp/ci-generated.hcl <<'PWPOLICY'
length = 32
rule "charset" {
  charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
}
PWPOLICY
  bao write sys/policies/password/ci-generated policy=@/tmp/ci-generated.hcl >/dev/null
  bao policy write ci-acme-api - >/dev/null <<'POLICY'
path "secret/data/shared/ci-acme-api" {
  capabilities = ["create", "update"]
}
path "bitwarden/sync/ci-acme-api" {
  capabilities = ["update"]
}
path "sys/policies/password/ci-generated/generate" {
  capabilities = ["read"]
}
POLICY
  bao auth list -format=json | jq -e 'has("approle/")' >/dev/null || bao auth enable approle >/dev/null
  bao write auth/approle/role/ci-acme-api \
    token_policies=ci-acme-api token_ttl=10m token_max_ttl=30m >/dev/null

  # Developers see a clearly marked pending item in the meantime.
  id="$(role_cipher_id ci-acme-api)"
  item="$(vault_item "$id")"
  eq "$(jq -c '[.fields[] | {name, value}]' <<<"$item")" \
    '[{"name":"status","value":"pending - will be filled by the acme-provision pipeline"}]' "placeholder item"
  eq "$(jq -r '.login.password' <<<"$item")" "null" "placeholder has no password"

  # Pipeline: logs in with its own identity, lets OpenBao generate the value,
  # stores it and triggers its sync.
  role_id="$(bao read -field=role_id auth/approle/role/ci-acme-api/role-id)"
  secret_id="$(bao write -f -field=secret_id auth/approle/role/ci-acme-api/secret-id)"
  ci="$(bao write -field=token auth/approle/login role_id="$role_id" secret_id="$secret_id")"
  generated="$(with_token "$ci" bao read -field=password sys/policies/password/ci-generated/generate)"
  eq "${#generated}" "32" "length of the generated value"
  with_token "$ci" bao kv put "$KV/ci-acme-api" \
    username=acme-api password="$generated" url=https://api.acme.example.com >/dev/null
  out="$(with_token "$ci" bao write -format=json -f "$MOUNT/sync/ci-acme-api")"
  eq "$(jq -r '.data.cipher_id' <<<"$out")" "$id" "the pipeline's sync updates the placeholder item"

  # What the pipeline identity cannot do.
  expect_fail "pipeline reads its own secret back" with_token "$ci" bao kv get "$KV/ci-acme-api"
  expect_fail "pipeline reads another secret" with_token "$ci" bao kv get "$KV/suite-grafana"
  expect_fail "pipeline overwrites another secret" with_token "$ci" bao kv put "$KV/suite-grafana" password=x
  expect_fail "pipeline writes a role" with_token "$ci" bao write "$MOUNT/roles/ci-evil" \
    source_path="secret/data/shared/suite-grafana" cipher_name="evil"
  expect_fail "pipeline reads the plugin config" with_token "$ci" bao read "$MOUNT/config"
  expect_fail "pipeline writes the plugin config" with_token "$ci" bao write "$MOUNT/config" sync_interval=1s
  expect_fail "pipeline syncs another role" with_token "$ci" bao write -f "$MOUNT/sync/social-acme"
  expect_fail "pipeline syncs every role" with_token "$ci" bao write -f "$MOUNT/sync"

  # Developers: same item, now with the real value and without the marker.
  item="$(vault_item "$id")"
  eq "$(jq -r '.login.username' <<<"$item")" "acme-api" "username"
  eq "$(jq -r '.login.password' <<<"$item")" "$generated" "password the Developer sees"
  eq "$(jq -c '.fields' <<<"$item")" "[]" "placeholder marker is gone"
}

# The option the playbook advises against: a role whose source path does not
# exist yet. A manual sync fails with a clear error and publishes nothing.
case_wow_role_without_source() {
  local admin
  admin="$(token_for bitwarden-admin)"
  with_token "$admin" bao write "$MOUNT/roles/suite-not-yet" \
    source_path="secret/data/shared/suite-not-yet" cipher_name="Suite not yet" \
    collection_ids="$E2E_COLLECTION_ID" >/dev/null
  expect_fail "sync of a role without a source secret" with_token "$admin" bao write -f "$MOUNT/sync/suite-not-yet"
  grep -q 'secret not found at "secret/data/shared/suite-not-yet"' <<<"$out" || die "unexpected error: $out"
  eq "$(role_cipher_id suite-not-yet)" "" "no item was created"
  with_token "$admin" bao delete "$MOUNT/roles/suite-not-yet" >/dev/null
}

# Scenario 4. Needs: as developer.
case_wow_decommission() {
  local admin id
  admin="$(token_for bitwarden-admin)"
  id="$(role_cipher_id social-acme)"

  with_token "$admin" bao delete "$MOUNT/roles/social-acme" >/dev/null
  vault_lacks "$id"
  bao kv metadata delete "$KV/social-acme" >/dev/null
  expect_fail "read of the deleted KV secret" bao kv get "$KV/social-acme"
  json_ok "$(with_token "$admin" bao list -format=json "$MOUNT/roles")" \
    'index("social-acme") == null' "role is no longer listed"
}

# --- cases: collections and folders ---------------------------------------------

case_collections_api() {
  local resp
  resp="$(curl -sS -X LIST -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/$MOUNT/collections")"
  case "$E2E_SYNC_MEMBER_TYPE" in
    owner | admin)
      json_ok "$resp" '.data.total == 2' "two collections"
      json_ok "$resp" "any(.data.collections[]; .name == \"OpenBao Synced\" and .id == \"$E2E_COLLECTION_ID\")" \
        "decrypted collection name"
      ;;
    *)
      # Vaultwarden 1.35.4 lets only organization admins and owners list an
      # organization's collections. With the least-privilege sync account the
      # path fails; syncing into a known collection ID is not affected.
      json_ok "$resp" '.errors | length > 0' "collections/ fails for a sync account with the $E2E_SYNC_MEMBER_TYPE role"
      grep -q 'listing collections' <<<"$resp" || die "unexpected error: $resp"
      ;;
  esac
}

case_folders_api() {
  local resp
  bao write -f "$MOUNT/folders/suite-folder" >/dev/null
  resp="$(curl -sS -X LIST -H "X-Vault-Token: $BAO_TOKEN" "$BAO_ADDR/v1/$MOUNT/folders")"
  json_ok "$resp" '[.data.folders[] | select(.name == "suite-folder")] | length == 1' "folder is listed by the API"
}

# Known defect: folders/ and collections/ answer a LIST request without a
# `keys` entry, and the bao CLI (2.5.1) then prints {} and exits 2, although
# the documentation tells the reader to use `bao list -format=json`.
known_bao_list_unusable() {
  local rc=0 printed
  printed="$(bao list -format=json "$MOUNT/folders" 2>&1)" || rc=$?
  eq "$rc" "2" "exit code of bao list on folders/"
  eq "$printed" "{}" "output of bao list on folders/"
}

# Known defect: collections/:role/assign sends PUT /api/ciphers/<id>/collections/admin,
# which Vaultwarden 1.35.4 does not serve (404), whatever the sync account's
# role. The role's stored collection_ids stay as they were.
known_assign_fails() {
  expect_fail "collections/:role/assign" \
    bao write "$MOUNT/collections/suite-grafana/assign" collection_ids="$E2E_COLLECTION_SECONDARY_ID"
  grep -q 'update collections returned status 404' <<<"$out" || die "expected a 404 from the vault, got: $out"
  eq "$(bao read -format=json "$MOUNT/roles/suite-grafana" | jq -c '.data.collection_ids')" \
    "[\"$E2E_COLLECTION_ID\"]" "collection_ids stored on the role"
}

# --- cases: removal -------------------------------------------------------------

# Needs: as developer.
case_delete_sync() {
  local id out
  id="$(role_cipher_id suite-postgres)"
  out="$(bao delete -format=json "$MOUNT/sync/suite-postgres" | jq '.data')"
  eq "$(jq -r '.deleted_cipher_id' <<<"$out")" "$id" "deleted_cipher_id"
  vault_lacks "$id"
  # The role survives without an item ID and can be synced again.
  eq "$(bao read -field=cipher_name "$MOUNT/roles/suite-postgres")" "Suite Postgres" "role still exists"
  eq "$(role_cipher_id suite-postgres)" "" "cipher_id cleared on the role"
}

case_delete_role() {
  local id
  id="$(role_cipher_id suite-grafana)"
  bao delete "$MOUNT/roles/suite-grafana" >/dev/null
  vault_lacks "$id"
  expect_fail "read of the deleted role" bao read "$MOUNT/roles/suite-grafana"
}

# --- cases: personal vault (no organization_id) ---------------------------------

# Known defect: the documentation says that without bao_token the plugin uses
# the token of the calling request. In a real OpenBao the plugin does not get
# a usable caller token, so the source read is refused even for a root caller.
known_no_caller_token_fallback() {
  bao secrets enable -path="$PERSONAL_MOUNT" "$PLUGIN" >/dev/null
  bao write "$PERSONAL_MOUNT/config" \
    url="$E2E_VW_URL" email="$E2E_SYNC_EMAIL" password="$E2E_SYNC_PASSWORD" \
    bao_addr="$BAO_ADDR" >/dev/null
  bao write "$PERSONAL_MOUNT/roles/suite-personal" \
    source_path="secret/data/shared/suite-api-keys" cipher_name="Suite personal note" cipher_type=2 >/dev/null
  expect_fail "sync without bao_token" bao write -f "$PERSONAL_MOUNT/sync/suite-personal"
  grep -q 'permission denied' <<<"$out" || die "expected 'permission denied', got: $out"
}

# Needs: as sync. A personal item is visible to the sync account only, which
# is why this mode is for testing and not for sharing.
case_personal_vault() {
  local token id item
  token="$(bao token create -orphan -policy=bitwarden-e2e-sync-read -ttl=1h -field=token)"
  bao write "$PERSONAL_MOUNT/config" bao_token="$token" >/dev/null
  bao write -f "$PERSONAL_MOUNT/sync/suite-personal" >/dev/null
  id="$(bao read -field=cipher_id "$PERSONAL_MOUNT/roles/suite-personal")"

  item="$(vault_item "$id")"
  eq "$(jq -r '.name' <<<"$item")" "Suite personal note" "item name"
  eq "$(jq -r '.organizationId' <<<"$item")" "null" "item belongs to no organization"
  eq "$(jq -c '.collectionIds' <<<"$item")" "[]" "item is in no collection"

  bao delete "$PERSONAL_MOUNT/roles/suite-personal" >/dev/null
  vault_lacks "$id"
  bao secrets disable "$PERSONAL_MOUNT" >/dev/null
}

# --- run ------------------------------------------------------------------------

started=$SECONDS
echo "bao $(bao version | head -n1), bw $(bw --version), sync account: $E2E_SYNC_MEMBER_TYPE with '$E2E_SYNC_COLLECTION_ACCESS' access"

run "plugin: registered by SHA-256 and running inside a real OpenBao" case_plugin_registered
run "status: vault reachable, authenticated, ok" case_status_ok
run "config: read never returns password or bao_token" case_config_redacted
run "TLS: plugin -> Vaultwarden over https with a private CA, plugin -> OpenBao over the compose network" case_tls

as admin
run "identities: Admin owns the organization, sync account and Developer are plain members" case_three_identities

as developer
run "JTBD: share a secret - role + sync, Developer sees the item in the read-only collection" case_share
run "fields: unmapped KV keys appear as text custom fields" case_custom_fields
run "JTBD: rotate in OpenBao, Developer sees the new value (same item ID)" case_rotate
run "JTBD: Developer cannot edit, delete or add items in the shared collection" case_developer_read_only
run "JTBD: inventory - roles/, sync/ and status show what is published" case_inventory
run "sync-all: every role is pushed, secure note included" case_sync_all
run "least privilege: a path outside the bao_token policy is not synced" case_scoped_token
run "Scenario 1: a Developer adds a new shared account - write-only intake, Admin publishes, Developers see it" case_wow_new_shared_account
run "Scenario 2: manual rotation at a vendor - new value into KV, sync, members see it" case_wow_manual_rotation
run "Scenario 3: compromised secret - forced sync, confirmation, old KV versions destroyed" case_wow_compromise
run "Scenario 5: CI/CD - placeholder approved, pipeline identity fills it, Developer sees the real value" case_wow_cicd_placeholder
run "Scenario 5 (warning): a role without a source secret fails to sync and publishes nothing" case_wow_role_without_source
run "Scenario 4: decommissioned account - role, item and KV history are gone" case_wow_decommission
run "JTBD: periodic sync picks up a rotation without a manual sync" case_periodic

as admin
run "JTBD: one source of truth - a manual edit in the vault is overwritten by the next sync" case_manual_edit_overwritten

run "collections/: API result matches the sync account's organization role" case_collections_api
run "folders/: create and list through the API" case_folders_api
known "bao CLI cannot print list responses of folders/ and collections/" \
  "list: bao list on folders/ prints {} and exits 2" known_bao_list_unusable
known "PUT /api/ciphers/<id>/collections/admin is 404 on Vaultwarden 1.35.4" \
  "assign: collections/:role/assign fails" known_assign_fails

as developer
run "delete sync/:name: item removed, role kept" case_delete_sync
run "JTBD: withdraw a secret - delete roles/:name removes the item for the Developer" case_delete_role

known "docs: 'the plugin tries the token of the calling request'" \
  "bao_token: without it a manual sync is refused (no caller-token fallback)" known_no_caller_token_fallback
as sync
run "personal vault: without organization_id the item lands in the sync account's own vault" case_personal_vault

echo
echo "Result: $pass passed, $known known issue(s) pinned, $failed failed in $((SECONDS - started))s"
if [ "$failed" -ne 0 ]; then
  printf 'Failed: %s\n' "${failed_names[@]}"
  exit 1
fi
