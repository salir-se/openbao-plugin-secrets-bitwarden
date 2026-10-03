# Operations

Examples assume the plugin is registered as `openbao-plugin-secrets-bitwarden` and
mounted at `bitwarden/`.

## Preparing the Bitwarden side

1. Create a dedicated account for the plugin. Set its KDF to PBKDF2-SHA256 and
   leave two-step login off.
2. Make it a member of the organization you sync into, with enough rights to
   create, edit and delete items in the target collections. Tested with
   Vaultwarden 1.35.4: the *User* role with edit access to those collections
   is enough. Listing collections through the plugin needs *Admin* or *Owner*.
   See [recommended-setup.md](recommended-setup.md).
3. Create the collections and share them read-only with the people or groups
   who need the credentials.
4. Note the organization UUID and the collection UUIDs. Both are visible in
   the web vault URLs, and `bw list organizations` and
   `bw list org-collections --organizationid <uuid>` print them.

Items in those collections are overwritten on every sync. Tell readers not to
edit them, for example through `notes_template`.

## Preparing the OpenBao side

- `plugin_directory` must be set in the server configuration and contain the
  binary.
- The plugin reads source secrets over the OpenBao HTTP API at `bao_addr`, not
  through an internal channel. That address must be reachable from the OpenBao
  host or container itself.
- Create a read-only policy for the source paths and a token bound to it, and
  store it as `bao_token`. The plugin never renews this token.

## Keep configuration reproducible

Roles and the connection config live only in the mount's storage. Keep the
`bao write .../config` and `bao write .../roles/*` commands in a script or in
your configuration management, with the secrets supplied from the environment.
You will need it after an upgrade (below) and for disaster recovery.

## Upgrading the plugin binary

In our experience `bao plugin reload` did not reliably pick up a replaced
binary. The procedure that has worked consistently is a full re-register and a
disable/enable of the mount:

```bash
# 1. Replace the binary in plugin_directory, then register the new checksum.
SHA=$(sha256sum /etc/openbao/plugins/openbao-plugin-secrets-bitwarden | cut -d' ' -f1)
bao plugin register -sha256="$SHA" secret openbao-plugin-secrets-bitwarden

# 2. Cycle the mount.
bao secrets disable bitwarden/
bao secrets enable -path=bitwarden openbao-plugin-secrets-bitwarden

# 3. Re-apply config and roles from your script, then sync.
./restore-bitwarden-sync.sh
bao write -f bitwarden/sync
```

### What the disable/enable cycle destroys

Disabling a secrets mount deletes its storage. For this plugin that is:

- `config`: URL, email, master password, organization ID, `bao_addr`,
  `bao_token`, `sync_interval`
- every `role/<name>`, including the stored `cipher_id` and `synced_at`

It does **not** touch the vault. Items already synced stay in Bitwarden.

After you re-create the roles, the first sync of each role has no `cipher_id`,
so the plugin looks the item up by `cipher_name`, adopts it and updates it in
place. No duplicates are created as long as `cipher_name` is unchanged. If you
rename `cipher_name` at the same time, the old item is orphaned and a new one
is created.

## Restarts

Session tokens, decrypted keys, change-detection hashes and the last periodic
run time are in memory. After an OpenBao restart, unseal or plugin restart the
plugin logs in again on first use, and the first periodic cycle pushes every
role once.

## Removing things

| Goal | Command | Effect |
|------|---------|--------|
| Stop syncing one role, keep its item | no per-role command | Deleting a role also deletes its item. Only disabling the whole mount drops roles without touching the vault |
| Remove the item, keep the role | `bao delete bitwarden/sync/<role>` | Item permanently deleted; the next sync re-creates it |
| Remove role and item | `bao delete bitwarden/roles/<role>` | Item deletion is best effort; the role is removed regardless |
| Remove everything on the OpenBao side | `bao secrets disable bitwarden/` | Config and roles gone; vault items untouched |

## Logs

The plugin writes JSON log lines to stderr, which OpenBao forwards into its own
server log. Messages include the account email, role names, item names and
item IDs. Secret values are not logged. Login failures include the server's
error response body.

## Troubleshooting

**`unsupported KDF type: 1 (only PBKDF2 / type 0 is supported)`**
The account uses Argon2id. Change the KDF to PBKDF2-SHA256 in the account's
security settings in the web vault, then retry.

**`login returned status 400: ...`**
Wrong email or master password, or the server demands something the plugin
does not send, such as a two-factor code. The response body after the status
code says which.

**`no token available: set bao_token in config`**
The sync had neither a configured `bao_token` nor a caller token. Periodic
sync always hits this without `bao_token`.

**`reading from "...": ... permission denied`**
The token in use cannot read `source_path`. Check the policy bound to
`bao_token`. When OpenBao runs the plugin as an external process, the caller's
token is generally not usable for reading other mounts, so configure
`bao_token` rather than relying on the fallback.

**`secret not found at "..."`**
`source_path` does not exist. For KV v2 the path contains `data/`:
`secret/data/grafana`, not `secret/grafana`.

**`organization <id> not found or no key available`**
The account's sync data contains no decryptable key for that organization.
Confirm the account is a confirmed member and that `organization_id` is right.
The plugin log shows the specific decryption failure.

**`getting org encryption keys` errors after the account's membership changed**
Organization keys are cached per session. Rewrite `config` (any field) to drop
the session and force a fresh login.

**`status` reports `vaultwarden_reachable: false` but syncs work**
`status` probes `<url>/alive`. A server or proxy that does not serve that path
fails the probe even though the API works.

**Duplicate items in the vault**
When an update fails, the plugin falls back to creating a new item and points
the role at it, which leaves the previous item behind. Delete the stale one by
hand. If instead you clear the link with `bao delete bitwarden/sync/<role>`
and sync again, the name lookup removes all but the newest match.

**An item someone created by hand was overwritten or deleted**
On first sync the plugin adopts any item whose name equals `cipher_name` and
deletes other items with the same name. Give synced items names that do not
collide with manually managed ones.

**Changes to a role are not showing up**
Periodic sync only reacts to changes in the source secret. Run
`bao write -f bitwarden/sync/<role>`.

**Collection change on a role has no effect**
`collection_ids` on the role is applied when the item is created. For an
existing item use `bao write bitwarden/collections/<role>/assign`.

**Plugin does not start, or OpenBao reports a checksum mismatch**
Check that the binary is statically linked (`CGO_ENABLED=0`), executable by
the OpenBao user, built for the server's OS and architecture, and that the
SHA-256 passed to `bao plugin register` is that of the file currently in
`plugin_directory`.
