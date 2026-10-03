# API reference

All paths are relative to the mount point. Examples assume the plugin is
mounted at `bitwarden/`. In OpenBao CLI terms, "write" is `bao write` (HTTP
POST/PUT), "read" is `bao read` (GET), "list" is `bao list` (LIST) and
"delete" is `bao delete` (DELETE).

- [config](#config)
- [status](#status)
- [info](#info)
- [roles](#roles)
- [sync](#sync)
- [collections](#collections)
- [folders](#folders)

## config

Connection settings. Stored at the storage key `config`.

| Operation | Behaviour |
|-----------|-----------|
| write | Creates or partially updates the configuration. Omitted fields keep their stored value. `url`, `email` and `password` must be non-empty after the merge |
| read | Returns the non-secret settings. `password` and `bao_token` are never returned |
| delete | Removes the configuration |

Every write or delete drops the cached Bitwarden session. The next operation
logs in again.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `url` | string | yes | | Base URL of the Bitwarden-compatible server. A trailing slash is ignored |
| `email` | string | yes | | Account email |
| `password` | string | yes | | Account master password. The account must use PBKDF2 |
| `organization_id` | string | no | | Organization that owns synced items. When empty, items go to the account's personal vault and the `collections/` paths are unusable |
| `bao_addr` | string | no | `http://127.0.0.1:8200` | OpenBao API address for reading source secrets |
| `bao_token` | string | no | | OpenBao token for reading source secrets. When set, it is used for every source read instead of the caller's token. When empty, the token of the calling request is used |
| `bao_tls_skip_verify` | bool | no | `false` | Skip TLS certificate verification for requests to `bao_addr` |
| `sync_interval` | string | no | | Go duration (`10m`, `1h`). Empty, `0`, or a value that does not parse disables periodic sync |

## status

`read status` runs a live check and always returns a response, even when the
plugin is not configured. It makes outbound requests to the Bitwarden server:
the reachability probe and, if no session is cached, a login.

| Field | Description |
|-------|-------------|
| `configured` | A configuration is stored |
| `vaultwarden_reachable` | `GET <url>/alive` returned 200 within 5 seconds |
| `authenticated` | A session exists or a login succeeded. Only attempted when the server is reachable |
| `ok` | All three of the above are true |
| `url`, `sync_interval` | From the configuration |
| `total_roles`, `synced_roles`, `unsynced_roles` | Role counts. "Synced" means the role has a stored item ID |
| `last_periodic_sync` | RFC 3339 time of the last periodic run in this plugin process, or empty |
| `vaultwarden_error`, `auth_error`, `error`, `message` | Present only when the corresponding step failed |

## info

`read info` returns a static endpoint summary and quick-start text together
with `configured`, `total_roles`, `synced_roles`, `sync_interval` and
`last_sync`. It makes no network calls.

`list` on the mount root returns the top-level sections.

## roles

A role maps one source secret to one vault item. Stored at `role/<name>`.

| Operation | Path | Behaviour |
|-----------|------|-----------|
| list | `roles/` | Role names. `key_info` carries `cipher_name`, `cipher_type`, `source_path`, `cipher_id`, `synced`, `synced_at` per role |
| write | `roles/:name` | Creates or partially updates a role. Does not contact Bitwarden |
| read | `roles/:name` | The role definition plus `cipher_id` and `synced_at`. Only the mapping fields for the role's `cipher_type` are returned |
| delete | `roles/:name` | Deletes the role. If the role has a synced item, the plugin first tries to delete it from the vault. A failure there is logged and the role is deleted anyway |

Role names are lowercased.

### Common fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `source_path` | string | yes | | API path of the source secret, as it appears after `/v1/`. For KV v2: `<mount>/data/<path>`. For KV v1: `<mount>/<path>` |
| `cipher_name` | string | yes | | Item name shown in Bitwarden. Also the key used to find an existing item on first sync |
| `cipher_type` | int | no | `1` | `1` login, `2` secure note, `3` card, `4` identity |
| `collection_ids` | comma-separated list | no | | Collection UUIDs for the item. Sent when the item is created. To change the assignment of an existing item use `collections/:role/assign` |
| `folder_id` | string | no | | Folder ID to place the item in |
| `notes_template` | string | no | | Static text for the item's notes. It is not a template: no substitution is performed |

Read-only fields set by the plugin: `cipher_id` (vault item ID) and
`synced_at` (RFC 3339, UTC).

Each `*_field` option below names a **key in the source secret**. If the key is
missing from the secret, the item field is left empty.

### Login fields (`cipher_type=1`)

| Field | Description |
|-------|-------------|
| `user_field` | Source key for the username |
| `pass_field` | Source key for the password |
| `url_field` | Source key for the primary URI |
| `extra_urls` | Comma-separated list of additional literal URIs, appended after the primary URI |

### Card fields (`cipher_type=3`)

`cardholder_name_field`, `brand_field`, `number_field`, `exp_month_field`,
`exp_year_field`, `code_field`.

### Identity fields (`cipher_type=4`)

`title_field`, `first_name_field`, `middle_name_field`, `last_name_field`,
`email_field`, `phone_field`, `company_field`, `ssn_field`,
`identity_user_field`, `passport_number_field`, `license_number_field`,
`address1_field`, `address2_field`, `address3_field`, `city_field`,
`state_field`, `postal_code_field`, `country_field`.

### Secure notes (`cipher_type=2`)

No type-specific fields. The item consists of the name, the notes and custom
fields.

### Custom fields

Every key of the source secret that is not claimed by one of the `*_field`
options of the role is added to the item as a custom field of type text, with
the key as the field name and the value formatted as a string. For a secure
note this means every key. Custom fields are not marked hidden.

### Examples

```bash
# Login
bao write bitwarden/roles/grafana \
    source_path="secret/data/grafana" \
    cipher_name="Grafana admin" \
    user_field="username" pass_field="password" url_field="url" \
    extra_urls="https://grafana.internal.example.com" \
    collection_ids="<collection uuid>"

# Secure note: all keys of the secret become custom fields
bao write bitwarden/roles/api-keys \
    source_path="secret/data/api-keys" \
    cipher_name="API keys" cipher_type=2 \
    notes_template="Managed by OpenBao."

# Card
bao write bitwarden/roles/corp-card \
    source_path="secret/data/corp-card" \
    cipher_name="Corporate card" cipher_type=3 \
    cardholder_name_field="holder" number_field="number" \
    exp_month_field="exp_month" exp_year_field="exp_year" \
    code_field="cvv" brand_field="brand"
```

## sync

| Operation | Path | Behaviour |
|-----------|------|-----------|
| write | `sync/:name` | Syncs one role now. Returns `cipher_id`, `cipher_name`, `synced_at` |
| read | `sync/:name` | Stored sync state (`role`, `cipher_name`, `cipher_type`, `source_path`, `cipher_id`, `synced`, `synced_at`). If the role is synced, also fetches the item and adds `revision_date`, or `vaultwarden_error` on failure |
| delete | `sync/:name` | Permanently deletes the role's item from the vault, clears `cipher_id` and keeps the role. Returns `deleted_cipher_id`. Errors if the role has no synced item |
| write | `sync` | Syncs every role, regardless of whether its data changed. Returns `total`, `synced`, `failed` and a per-role `results` map. One failing role does not stop the others |
| list | `sync/` | Role names with `cipher_name`, `cipher_id`, `synced`, `synced_at`, `source_path` in `key_info` |

### What a sync does

1. Reads the source secret from `bao_addr` using `bao_token` (or the caller's
   token when `bao_token` is empty). For KV v2 responses the inner `data` map
   is used; otherwise the response data is used as is.
2. Selects the encryption keys: the organization key when `organization_id` is
   set, the user key otherwise.
3. Builds and encrypts the item.
4. If the role has no `cipher_id`, searches the vault for items whose decrypted
   name equals `cipher_name` (restricted to the organization when one is
   configured). The most recently revised match is adopted. **All other matches
   are permanently deleted.**
5. Updates the item if an ID is known, otherwise creates it. If the update
   fails for any reason, the plugin creates a new item instead.
6. Stores `cipher_id` and `synced_at` on the role. If that write fails the
   sync fails; a retry recovers the item through step 4.

Organization items are created through `POST /api/ciphers/create` and updated
and deleted through the `/admin` variants of the cipher endpoints. Personal
items use the plain cipher endpoints.

### Periodic sync

When `sync_interval` is a positive duration, OpenBao's periodic backend tick
drives the sync. The tick frequency is controlled by OpenBao, so the effective
resolution is no finer than that tick.

For each role the plugin reads the source secret, hashes it (SHA-256 over
sorted `key=value` lines) and syncs only when the hash differs from the last
one it pushed. The hashes and the last-run time are held in memory:

- After an OpenBao restart, unseal or plugin reload, the first periodic run
  pushes every role once.
- A change to a role definition alone does not trigger a periodic push. Run
  `write sync/:name`.
- A failed role is retried on the next interval.

Periodic sync has no calling request, so it needs `bao_token`.

## collections

Both paths require `organization_id`.

| Operation | Path | Behaviour |
|-----------|------|-----------|
| list | `collections/` | Returns `collections` (a list of `{id, name}` with decrypted names) and `total` |
| write | `collections/:role/assign` | Replaces the collection assignment of the role's item with `collection_ids` and stores the same list on the role. The role must already be synced |

`:role` is the role name, in lowercase. The response of `collections/` is not
a standard key list, so read it with `bao list -format=json`.

```bash
bao list -format=json bitwarden/collections
bao write bitwarden/collections/grafana/assign collection_ids="<uuid-1>,<uuid-2>"
```

## folders

Folders belong to the plugin's own Bitwarden account and their names are
encrypted with that account's user key, not the organization key.

| Operation | Path | Behaviour |
|-----------|------|-----------|
| list | `folders/` | Returns `folders` (a list of `{id, name}` with decrypted names) and `total`. Use `-format=json` |
| write | `folders/:name` | Creates a folder called `:name`. Returns `id` and `name`. Writing the same name twice creates two folders |
| delete | `folders/:id` | Deletes the folder with that ID |

The name is part of the path, so it is limited to letters, digits, `_`, `-`
and `.`.
