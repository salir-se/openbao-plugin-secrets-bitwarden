# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries are grouped in the categories OpenBao uses: Features, Improvements,
Changes (need action from the operator), Deprecations and Bugs. See
[CONTRIBUTING.md](CONTRIBUTING.md#changelog-entries).

## [Unreleased]

## [0.1.0] - 2026-10-03

Initial public release. The code was developed in a private repository under
the name `openbao-plugin-secrets-vaultwarden` and is published here as
`openbao-plugin-secrets-bitwarden` under the MIT license
(Copyright (c) 2026 artfulbits.se | salir.se project).

### Features

- The plugin syncs secrets one way, from OpenBao KV (v1 or v2) to a
  Bitwarden-compatible server. It is developed and tested against Vaultwarden;
  the official Bitwarden server is untested.
- Items are encrypted client-side the way Bitwarden clients do it:
  PBKDF2-SHA256 key derivation, HKDF-Expand key stretching, AES-256-CBC with
  HMAC-SHA256 item encryption, and RSA-OAEP-SHA1 or AES decryption of
  organization keys.
- The `config` path holds the server URL, account credentials, organization,
  the OpenBao address and token used to read source secrets (TLS verified by
  default, `bao_tls_skip_verify` to opt out), and `sync_interval`.
- The `roles/` paths map a source secret to a vault item of type login, secure
  note, card or identity, with collection and folder assignment, static notes
  and extra URIs. Unmapped source keys become custom fields.
- The `sync/` paths sync one role or all roles, report sync state, and delete
  a role's item while keeping the role.
- Periodic sync, driven by `sync_interval`, pushes only roles whose source
  data changed.
- On a role's first sync, an existing item with the same name is adopted and
  further items with that name are removed.
- The `collections/` paths list organization collections and reassign an item.
- The `folders/` paths list, create and delete folders of the plugin's
  account.
- The `status` and `info` paths provide connectivity checks and a built-in
  endpoint summary.
- Releases are built by GoReleaser from version tags as static linux and
  darwin binaries for amd64 and arm64, with SHA-256 checksums.

### Known limitations

- Argon2id accounts and accounts with two-step login are not supported.
- Source secrets are read with the configured `bao_token`, not the caller's
  token. Unmapped source keys are synced as visible custom fields. Items are
  matched by name on first sync. The full list is in `SECURITY.md`.
- Upgrading the binary requires re-registering the plugin and a
  disable/enable cycle of the mount, which removes the stored configuration
  and roles. See `docs/operations.md`.

[Unreleased]: https://github.com/salir-se/openbao-plugin-secrets-bitwarden/commits/main
[0.1.0]: https://github.com/salir-se/openbao-plugin-secrets-bitwarden/releases/tag/v0.1.0
