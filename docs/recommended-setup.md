# Recommended setup, step by step

This takes you from the [prerequisites](prerequisites.md) to the configuration
the [README](../README.md#recommended-setup) recommends: an organization owned
by a human **Admin**, a dedicated **sync account** the plugin logs in as, and
**Developers** who read the synced items with their own accounts.

Every `bao` and `bw` command on this page was run in the
[end-to-end environment](e2e.md) (OpenBao 2.5.1, Vaultwarden 1.35.4, Bitwarden
CLI 2026.2.0) with that environment's addresses and fixture accounts in place
of the placeholders. The steps marked *web vault* are done by a person in the
browser. The environment performs them through the server's API instead (see
`e2e/bootstrap`), so the clicks themselves are not tested here.

| Identity | Who holds its master password | In Bitwarden | In OpenBao |
|----------|-------------------------------|--------------|------------|
| **Admin** (human) | The Admin | Owns the organization; manages collections and members | Administers the plugin mount |
| **Sync account** | Only OpenBao (`bitwarden/config`) | *User* with edit access to the target collections | None |
| **Developer** (human) | The Developer | Own vault, read-only access to shared collections | No policy on the plugin mount |

## Part 1: Admin, in Bitwarden

1. **Create the organization** with your own account (*web vault*: New
   organization). Your account becomes its owner. Keep it a personal account
   of a human, separate from the sync account, so that the organization does
   not depend on a password that only OpenBao knows.

2. **Create the sync account** (*web vault*: Create account, with a mailbox
   you control, for example `sync-bot@example.com`). In its security settings
   keep the KDF on PBKDF2-SHA256 and leave two-step login off. Give it a long
   random master password. You will store that password in OpenBao in part 2
   and nowhere else.

3. **Create the collection** for synced items (*web vault*: organization,
   Collections, New collection). Use it for synced items only: on a role's
   first sync the plugin adopts an existing item with the same name and
   deletes other items with that name.

4. **Add the sync account to the organization** (*web vault*: organization,
   Members, Invite member) with:

   - role: **User**
   - access to the collection from step 3: **edit items** (not read-only)

   Then accept the invitation as the sync account and confirm the member as
   the Admin. Tested with Vaultwarden 1.35.4: this is the least privilege
   that syncing works with.

   | Sync account's membership | Create, update, delete items | `collections/` listing |
   |---------------------------|------------------------------|------------------------|
   | User, read-only access | refused: `No rights to modify the collection` | fails (401) |
   | User, edit access | works | fails (401) |
   | User, manage access | works | fails (401) |
   | Manager, manage access | works | fails (404) |
   | Admin or Owner | works | works |

   If you want `collections/` to work, make the sync account an *Admin*.
   That also lets it manage members and collections, so prefer *User* and take
   the collection ID from `bw` (step 6).

5. **Invite each Developer** (*web vault*: Members, Invite member) with the
   role **User** and **read-only** ("view items") access to the collection.
   Developers use their own account and master password. Confirm each member
   after they accept.

6. **Note the IDs** the plugin needs. Logged in as the Admin:

   ```bash
   bw sync
   bw list organizations
   bw list org-collections --organizationid <organization uuid>
   ```

   Both IDs are also part of the web vault URLs of the organization and the
   collection.

## Part 2: Admin, in OpenBao

The plugin binary is installed and registered as described in the README
([Install](../README.md#install), [Register and enable](../README.md#register-and-enable)).

1. **A token for the plugin**, read-only and limited to the paths you sync.
   Whoever can write roles on the mount can publish everything this token can
   read ([#1](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/issues/1)).

   ```bash
   bao policy write bitwarden-sync-read - <<'EOF'
   path "secret/data/shared/*" {
     capabilities = ["read"]
   }
   EOF
   SYNC_TOKEN=$(bao token create -orphan -policy=bitwarden-sync-read -period=768h -field=token)
   ```

   The plugin does not renew the token. Replace it through `config` before it
   expires.

2. **Connect the plugin** as the sync account. `password` and `bao_token` are
   stored in the mount and never returned on read.

   ```bash
   bao write bitwarden/config \
       url="https://vault.example.com" \
       email="sync-bot@example.com" \
       password="<sync account master password>" \
       organization_id="<organization uuid>" \
       bao_addr="https://openbao.example.com:8200" \
       bao_token="$SYNC_TOKEN" \
       sync_interval="10m"
   bao read bitwarden/status
   ```

   `status` must show `ok true`. Always set `organization_id`: without it
   items go to the sync account's personal vault, which nobody else can read.

3. **Publish a first secret.**

   ```bash
   bao kv put secret/shared/grafana \
       username="admin" password="s3cret" url="https://grafana.example.com"

   bao write bitwarden/roles/grafana \
       source_path="secret/data/shared/grafana" \
       cipher_name="Grafana admin" \
       user_field="username" pass_field="password" url_field="url" \
       collection_ids="<collection uuid>" \
       notes_template="Managed by OpenBao. Edits here are overwritten."

   bao write -f bitwarden/sync/grafana
   bao read bitwarden/sync/grafana
   ```

   Always set `collection_ids`, and keep one credential per KV path: every key
   that no `*_field` option claims becomes a visible custom field.

4. **A policy for Admins of the mount.** Developers get no policy on it.

   ```bash
   bao policy write bitwarden-admin - <<'EOF'
   path "bitwarden/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   EOF
   ```

   A token with only this policy can manage `config`, roles and syncs, and
   cannot read the KV secrets themselves.

5. **Keep it reproducible.** Put the `config` and role commands in a script
   under review, as in [`examples/setup-roles.sh`](../examples/setup-roles.sh).
   You need it again after a plugin upgrade ([operations.md](operations.md)).

## Part 3: Developer

1. Log in with **your own** account, in the browser extension, an app, or:

   ```bash
   bw config server https://vault.example.com
   bw login
   export BW_SESSION="$(bw unlock --raw)"
   ```

2. Read the shared item:

   ```bash
   bw sync
   bw get item "Grafana admin"
   bw get password "Grafana admin"
   ```

3. You cannot change it. Tested with the Bitwarden CLI 2026.2.0 against
   Vaultwarden 1.35.4, as a member with read-only access:

   - `bw edit item` leaves the item unchanged on the server (the command
     itself exits 0 and prints the unchanged item)
   - `bw delete item` answers `You do not have permission to delete this item.`
   - `bw create item` into the collection answers
     `No rights to modify the collection`

   If the value is wrong, tell the Admin. The fix goes into OpenBao.

## After a rotation

```bash
bao kv patch secret/shared/grafana password="<new value>"
bao write -f bitwarden/sync/grafana     # or wait for the periodic sync
```

The Developer sees the new value after the next `bw sync` (the apps sync on
their own schedule). More in [way-of-working.md](way-of-working.md).
