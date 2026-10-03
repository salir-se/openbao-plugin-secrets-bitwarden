# openbao-plugin-secrets-bitwarden

[![CI](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/salir-se/openbao-plugin-secrets-bitwarden)](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [OpenBao](https://openbao.org) secrets-engine plugin that pushes secrets
from OpenBao KV into a Bitwarden-compatible vault, one way.

OpenBao stays the source of truth. When a credential is rotated in OpenBao, the
plugin rewrites the matching vault item, so people who read passwords through
Bitwarden apps, browser extensions or the CLI see the current value without
anyone copying it by hand. Nothing is ever read back from Bitwarden into
OpenBao.

## Status and compatibility

- This is an independent, community-maintained external plugin, released from
  its own repository as OpenBao's
  [plugin policy](https://openbao.org/community/policies/plugins/) describes
  for external plugins. It is not affiliated with or endorsed by the OpenBao
  project or Bitwarden Inc. Bitwarden and OpenBao are trademarks of their
  respective owners.
- Pre-1.0. Paths and field names may still change between minor versions.
- The plugin speaks the Bitwarden client API. It is developed and tested
  against [Vaultwarden](https://github.com/dani-garcia/vaultwarden).
- **The official Bitwarden server (cloud or self-hosted) is untested.** One
  known gap: the `status` endpoint probes `<url>/alive`, which is a Vaultwarden
  route.
- The Bitwarden account must use the **PBKDF2-SHA256** KDF. Argon2id is not
  implemented, and login fails with `unsupported KDF type: 1`.
- The plugin logs in with email and master password only. It sends no
  two-factor token, so use an account without two-step login.
- Built against the OpenBao SDK v2 (`github.com/openbao/openbao/sdk/v2`).
- Parts of this repository (at minimum the unit tests, documentation and CI
  configuration) were produced with generative AI assistance under maintainer
  direction. See [CONTRIBUTING.md](CONTRIBUTING.md#ai-assisted-contributions).

## How it works

```
OpenBao KV  --read-->  openbao-plugin-secrets-bitwarden  --encrypted item-->  Bitwarden / Vaultwarden
(source of truth)      (runs inside OpenBao)                        organization collections
                                                                            |
                                                              apps, extensions, CLI (read-only users)
```

1. A **role** maps one KV secret to one vault item: which KV fields become the
   username, password and URI, which collections the item belongs to.
2. A **sync**, either on demand or on a timer, reads the KV secret over the
   OpenBao HTTP API, builds the item, encrypts it and creates or updates it in
   the vault. The item ID is stored on the role so later syncs update in place.
3. With `sync_interval` set, the plugin re-checks every role on that interval
   and pushes only the ones whose KV data changed.

### Client-side encryption

A Bitwarden server stores only ciphertext, so the plugin has to do what a
Bitwarden client does (`crypto.go`):

| Step | Mechanism |
|------|-----------|
| Master key | PBKDF2-SHA256 over the master password, salt = lowercased email, iteration count from the server's prelogin response |
| Stretched keys | HKDF-Expand-SHA256 with info `enc` and `mac`, 32 bytes each |
| Login hash | PBKDF2-SHA256(master key, master password, 1 iteration), base64 |
| User key | 64-byte symmetric key from the login response, decrypted with the stretched keys |
| Organization key | Taken from `/api/sync`; RSA-2048-OAEP-SHA1 (type 4, decrypted with the account's private key) or AES (type 2) |
| Item fields | AES-256-CBC with PKCS#7 padding and HMAC-SHA256 over IV and ciphertext, encoded as `2.<iv>\|<ciphertext>\|<mac>` |

Every item field (name, notes, username, password, URIs, custom field names
and values) is encrypted separately before it leaves OpenBao. Organization
items use the organization key, personal items the user key.

## Install

### From a release

Releases are built and published by GitHub Actions from version tags. Download
the build for your platform and `checksums.txt` from
[GitHub Releases](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/releases)
(linux and darwin, amd64 and arm64). Each platform is published both as a bare
binary and as a `.tar.gz` archive. The bare binary's checksum is the value
`bao plugin register` needs.

```bash
VERSION=0.1.0
BASE=https://github.com/salir-se/openbao-plugin-secrets-bitwarden/releases/download/v${VERSION}
curl -fLO "${BASE}/openbao-plugin-secrets-bitwarden_${VERSION}_linux_amd64"
curl -fLO "${BASE}/checksums.txt"
sha256sum --ignore-missing -c checksums.txt

# Optional: check it was built by this repository's release workflow
gh attestation verify "openbao-plugin-secrets-bitwarden_${VERSION}_linux_amd64" \
    --repo salir-se/openbao-plugin-secrets-bitwarden

install -m 0755 "openbao-plugin-secrets-bitwarden_${VERSION}_linux_amd64" \
    /etc/openbao/plugins/openbao-plugin-secrets-bitwarden
```

### From an OCI image (declarative install)

OpenBao can download and register plugins declared in the server
configuration. Each release publishes a signed multi-arch image (linux/amd64 and linux/arm64)
at `ghcr.io/salir-se/openbao-plugin-secrets-bitwarden`. The release notes of
each version list the pinned `tag@sha256:...` reference and the `cosign verify`
command.

```hcl
plugin_directory     = "/etc/openbao/plugins"
plugin_auto_download = true

plugin "secret" "bitwarden" {
  image = "ghcr.io/salir-se/openbao-plugin-secrets-bitwarden:v0.1.0@sha256:<image digest>"
}
```

Pin the image by digest, or set `sha256sum` to the plugin binary's SHA-256
when you do not. With `plugin_auto_register` at its default of `true`, the
plugin is registered at startup under the name in the stanza, so skip the
`bao plugin register` step below and enable it with
`bao secrets enable -path=bitwarden bitwarden`. See OpenBao's
[declarative plugins](https://openbao.org/docs/configuration/plugins)
reference for all parameters and for the OpenBao version that introduced them.

### From source

Requires the Go version named in `go.mod` or newer.

```bash
git clone https://github.com/salir-se/openbao-plugin-secrets-bitwarden.git
cd openbao-plugin-secrets-bitwarden
make build
# equivalent:
CGO_ENABLED=0 go build -o openbao-plugin-secrets-bitwarden ./cmd/openbao-plugin-secrets-bitwarden
```

Build with `CGO_ENABLED=0`. OpenBao executes the plugin as a subprocess in its
own environment, often a container with a different libc from your build host,
and a dynamically linked binary can fail to start there. Release binaries are
static.

## Register and enable

1. Set `plugin_directory` in the OpenBao server configuration and copy the
   binary into it, executable by the OpenBao user:

   ```hcl
   plugin_directory = "/etc/openbao/plugins"
   ```

2. Register the binary with its SHA-256 and enable a mount:

   ```bash
   SHA=$(sha256sum /etc/openbao/plugins/openbao-plugin-secrets-bitwarden | cut -d' ' -f1)
   bao plugin register -sha256="$SHA" secret openbao-plugin-secrets-bitwarden
   bao secrets enable -path=bitwarden openbao-plugin-secrets-bitwarden
   ```

The mount path is your choice. This documentation uses `bitwarden/`.

## Quick start

The usual setup: a dedicated Bitwarden account owns an organization, the plugin
writes items into that organization's collections, and the collections are
shared read-only with the people who need the credentials.

```bash
# 1. A token the plugin uses to read the source secrets (see Security).
bao policy write bitwarden-sync-read - <<'EOF'
path "secret/data/*" {
  capabilities = ["read"]
}
EOF
SYNC_TOKEN=$(bao token create -policy=bitwarden-sync-read -period=768h -field=token)

# 2. Connect the plugin to the vault.
bao write bitwarden/config \
    url="https://vault.example.com" \
    email="sync-bot@example.com" \
    password="<master password>" \
    organization_id="<organization uuid>" \
    bao_addr="https://openbao.example.com:8200" \
    bao_token="$SYNC_TOKEN" \
    sync_interval="10m"

# 3. Check connectivity and login.
bao read bitwarden/status

# 4. Find the collection to publish into.
bao list -format=json bitwarden/collections

# 5. The secret in OpenBao (KV v2 mounted at secret/).
bao kv put secret/grafana \
    username="admin" password="s3cret" url="https://grafana.example.com"

# 6. Map it to a vault item. KV v2 paths need the data/ segment.
bao write bitwarden/roles/grafana \
    source_path="secret/data/grafana" \
    cipher_name="Grafana admin" \
    user_field="username" pass_field="password" url_field="url" \
    collection_ids="<collection uuid>" \
    notes_template="Managed by OpenBao. Edits here are overwritten."

# 7. Push it now, then inspect.
bao write -f bitwarden/sync/grafana
bao read bitwarden/sync/grafana
```

After a rotation, `bao kv put secret/grafana password=...` is enough: the next
periodic cycle pushes the change. Run `bao write -f bitwarden/sync/grafana` to
push immediately, or `bao write -f bitwarden/sync` to push every role.

## Configuration

`bao write bitwarden/config ...` Writes are partial updates: fields you omit
keep their stored value.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | yes | | Base URL of the Bitwarden-compatible server |
| `email` | yes | | Account the plugin logs in as |
| `password` | yes | | Master password of that account. Never returned on read |
| `organization_id` | no | | Organization that owns the synced items. Empty means the account's personal vault |
| `bao_addr` | no | `http://127.0.0.1:8200` | OpenBao API address the plugin reads source secrets from |
| `bao_token` | no | | OpenBao token used to read source secrets. Never returned on read |
| `bao_tls_skip_verify` | no | `false` | Skip TLS certificate verification for requests to `bao_addr` |
| `sync_interval` | no | disabled | Go duration such as `10m` or `1h`. Empty or `0` disables periodic sync |

`sync_interval` is not validated on write. A value that does not parse as a Go
duration silently disables periodic sync.

Set `bao_token` if you use periodic sync. Without it the plugin falls back to
the token of the request that triggered the sync, and a periodic run has no
such request.

## API

All paths are relative to the mount. Field-level detail, response shapes and
behaviour notes are in [docs/api-reference.md](docs/api-reference.md).

| Path | Operations | Purpose |
|------|------------|---------|
| `config` | read, write, delete | Connection settings |
| `status` | read | Reachability, login check, role counts |
| `info` | read | Built-in endpoint summary and counters |
| `roles/` | list | Role names with sync metadata |
| `roles/:name` | read, write, delete | Role mapping. Delete also removes the vault item |
| `sync/` | list, write | List sync state, or sync all roles |
| `sync/:name` | read, write, delete | Sync state, force sync, or remove the vault item and keep the role |
| `collections/` | list | Organization collections with decrypted names |
| `collections/:role/assign` | write | Replace the collection assignment of a role's item |
| `folders/` | list | Folders of the plugin's account |
| `folders/:name` | write, delete | Create a folder by name, delete one by ID |

Roles support four item types through `cipher_type`: login (1, default),
secure note (2), card (3) and identity (4).

Things to know before you create roles:

- **Unmapped KV fields become custom fields.** Every key in the source secret
  that no `*_field` option claims is added to the item as a plain-text custom
  field. Keep source secrets limited to what readers of the item may see.
- **`cipher_name` must be unique in the target vault.** On a role's first sync
  the plugin looks for existing items with that name, adopts the most recently
  revised one, and permanently deletes the other matches.
- **Removal is permanent.** `delete sync/:name` and `delete roles/:name` delete
  the item outright. It does not go to the trash.
- **Periodic sync watches KV data only.** After editing a role, run a manual
  sync to apply the change.

## Security considerations

**What the plugin holds.** The Bitwarden master password and, if set, an
OpenBao token. Both are stored in the mount's storage under `config`, inside
OpenBao's encrypted barrier storage, and are never returned on read. Derived
keys, the account's RSA private key, organization keys and session tokens are
kept in process memory only.

**What it can reach.**

- In Bitwarden: everything the configured account can. Use a dedicated account
  whose access is limited to the organization you sync into. The plugin
  creates, updates and deletes items and creates and deletes folders.
- In OpenBao: whatever `bao_token` can read. When `bao_token` is set, source
  secrets are read with it, not with the caller's token, so the caller's own
  policies on the source paths are not consulted.

**Who can trigger it.** Anyone allowed to write `roles/*` and trigger a sync
can copy any path readable by `bao_token` into a collection. Give `bao_token`
a narrowly scoped, read-only policy covering only the source paths, and
restrict who may write `roles/*` on this mount. The plugin does not renew the
token; issue one that outlives your sync schedule and replace it through
`config` when it rotates.

**Transport.**

- Requests to the Bitwarden server use Go's default TLS verification against
  the system trust store. A private CA must be installed in the trust store of
  the host or container OpenBao runs in; there is no CA option. `url` is not
  restricted to `https://`, so do not configure a plain `http://` URL outside
  a test setup.
- Requests to `bao_addr` verify TLS certificates by default.
  `bao_tls_skip_verify=true` turns verification off; use it only on loopback
  or a network you trust.

**Visibility.** Organization members with access to a collection can read
every field of the items in it, including the custom fields generated from
unmapped keys of the source secret.

The full list of known limitations is in
[SECURITY.md](SECURITY.md#known-limitations). Read it before pointing the
plugin at a vault that also holds manually managed items.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `unsupported KDF type: 1` | The account uses Argon2id. Switch it to PBKDF2-SHA256 in the account's security settings |
| `plugin not configured: write to config/ first` | No `config` on this mount. Also the state after a disable/enable cycle |
| `no token available: set bao_token in config` | Periodic sync, or a caller without a usable token. Set `bao_token` |
| `secret not found at "..."` | Wrong `source_path`. For KV v2 it is `<mount>/data/<path>` |
| `organization <id> not found or no key available` | The account is not a confirmed member of that organization, or its key could not be decrypted. Check the plugin log |
| `status` shows `vaultwarden_reachable: false` | `<url>/alive` did not return 200 within 5 seconds. Check `url` and the network path from the OpenBao host |
| `bao list bitwarden/collections` prints nothing useful | The response is not a key list. Use `-format=json` |
| Plugin fails to start after install | Usually a dynamically linked binary. Rebuild with `CGO_ENABLED=0`, and check the registered SHA-256 matches the file |
| Old behaviour after replacing the binary | See the upgrade procedure in [docs/operations.md](docs/operations.md) |

More detail, including upgrades and what a disable/enable cycle does to stored
state, is in [docs/operations.md](docs/operations.md).

## Development

```bash
make build             # static plugin binary
make test              # unit tests, no external services
make test-integration  # OpenBao + Vaultwarden in Docker, then go test -tags integration
make cover             # unit tests with the coverage gate
make lint
make sha256            # SHA-256 of the built binary, for bao plugin register
make clean
```

Unit-test coverage must stay above 95%. `make cover` enforces the threshold
locally and CI runs the same gate, so a pull request that drops below it fails.

Unit tests mock the Bitwarden API over `httptest`. Integration tests
(`scripts/integration-test.sh`, `docker-compose.test.yml`) start throwaway
OpenBao and Vaultwarden containers on ports 18200 and 18080, register a test
account, and exercise login, key derivation, item create/update/delete and the
sync flow against a personal vault. Organization and collection handling is
covered by unit tests only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.
The policy is modelled on
[OpenBao's](https://github.com/openbao/openbao/blob/main/CONTRIBUTING.md):
commits need a DCO sign-off (`git commit --signoff`), and contributions must
not copy from source-available, GPL or AGPL code such as HashiCorp Vault,
Bitwarden or Vaultwarden. Unlike OpenBao, this project accepts AI-assisted
contributions when they are disclosed, reviewed and signed off by the
submitter.

## License

[MIT](LICENSE). Copyright (c) 2026 artfulbits.se | salir.se project.

This project is not affiliated with or endorsed by Bitwarden, Inc., the
Vaultwarden project or the OpenBao project.
