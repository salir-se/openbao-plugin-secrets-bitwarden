# Way of working

Recommendations for a team that runs its secrets through OpenBao and uses this
plugin to hand the human-facing ones to people. This is guidance, not a
feature list. Statements about what the plugin does are limited to what the
code does and what the [end-to-end suite](e2e.md) checks; the organisational
steps are suggestions to adapt.

The roles are those of the [README](../README.md#recommended-setup): the
**Admin** owns the Bitwarden organization and administers the plugin mount, a
**Developer** reads shared items with their own Bitwarden account, and the
**sync account** is what the plugin logs in as.

Every `bao` and `bw` command below was run in the end-to-end environment
(OpenBao 2.5.1, Vaultwarden 1.35.4, Bitwarden CLI 2026.2.0). Scenarios 1 to 5
are cases of the automated suite, under the same names.

| # | Scenario | Short answer |
|---|----------|--------------|
| 1 | [A Developer registers a new shared account](#1-a-developer-registers-a-new-shared-account) | Developer writes it to OpenBao (write-only), Admin publishes it through a reviewed role |
| 2 | [A secret is rotated by hand at a vendor](#2-a-secret-is-rotated-by-hand-at-a-vendor) | New value into the same KV path, sync, members' clients pick it up |
| 3 | [A secret is compromised](#3-a-secret-is-compromised) | Rotate at the target first, then KV, forced sync, confirm, clean up |
| 4 | [A vendor account is decommissioned](#4-a-vendor-account-is-decommissioned) | Close it at the vendor, delete the role (deletes the item), delete the KV secret |
| 5 | [CI/CD fills a secret a Developer asked for](#5-cicd-fills-a-secret-a-developer-asked-for) | Reviewed placeholder and role, pipeline identity that can write one path and trigger one sync |

## Ground rules

- **Which secrets go where.** Machine-to-machine secrets stay in OpenBao and
  are fetched by the workload itself (AppRole, Kubernetes or JWT auth, dynamic
  database credentials, short TTLs). Only secrets a person has to type or
  paste are published through this plugin: vendor consoles, third-party
  dashboards, shared service logins. Prefer SSO over a shared login where the
  target supports it.
- **Layout.** One KV path per credential, because every key a role does not
  map becomes a visible custom field. A path convention such as
  `<env>/<team>/<service>`. One collection per team and environment. Keep
  production apart, ideally on its own plugin mount with its own `bao_token`
  scoped to that environment's paths: whoever may write roles on a mount can
  publish everything that mount's token can read
  ([#1](https://github.com/salir-se/openbao-plugin-secrets-bitwarden/issues/1)).
- **Who may do what.** Only Admins get a policy on the plugin mount (`config`,
  `roles/*`, `sync/*`). Developers get none and need no OpenBao access to read
  shared secrets.
- **Configuration as code.** Keep the mount configuration and the role
  definitions in a reviewed repository and apply them with a script
  ([`examples/setup-roles.sh`](../examples/setup-roles.sh)). What is shared
  with whom then changes by pull request, and the setup can be re-applied
  after the disable/enable cycle a plugin upgrade needs
  ([operations.md](operations.md)).
- **The plugin propagates, it does not rotate.** A rotation happens at the
  target system. A value that was rotated away may still be in someone's
  clipboard or notes; only the target system refusing it revokes access.
- **What not to publish.** OpenBao root tokens, unseal or recovery keys, cloud
  root credentials, production database superuser passwords. Use dynamic
  secrets or a dedicated break-glass procedure. If break-glass credentials are
  published at all, give them their own collection with very few members.

The policies used in the scenarios:

```bash
# Admin: the plugin mount, and nothing else.
bao policy write bitwarden-admin - <<'EOF'
path "bitwarden/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Developer intake: may hand a credential to OpenBao, may not read any back.
bao policy write developer-intake - <<'EOF'
path "secret/data/shared/*" {
  capabilities = ["create", "update"]
}
EOF
```

Tested: `create` and `update` on the KV v2 `data/` path are all `bao kv put`
needs. Such a token cannot `bao kv get`, `bao kv list` or read metadata, and
`bao kv patch` is refused: `patch` needs the `patch` capability, or `read`
plus `update`.

## 1. A Developer registers a new shared account

*"I registered a social-network account that belongs to the organization. How
do I save it so that all developers can use it?"*

Developers cannot write to the plugin mount, and items in the shared
collection are read-only for them and overwritten by sync. The credential has
to enter through OpenBao.

1. **Developer**: register the account on a shared mailbox or alias the
   organization controls, not a personal address.
2. **Developer**: write the credential to the intake prefix. The token can
   write and cannot read.

   ```bash
   bao kv put secret/shared/social-acme \
       username=acme-social password='<password>' url=https://social.example.com
   ```

3. **Developer**: open a pull request in the configuration repository that
   adds the role definition (KV path, item name, field mapping, collection).
   No secret value is in it.
4. **Admin**: review, apply and sync.

   ```bash
   bao write bitwarden/roles/social-acme \
       source_path="secret/data/shared/social-acme" \
       cipher_name="Acme social" \
       user_field=username pass_field=password url_field=url \
       collection_ids="<collection shared with all developers>"
   bao write -f bitwarden/sync/social-acme
   ```

5. **Developers**: `bw sync`, or let the app sync. The item is there.
6. **Developer**: delete the copy from your personal vault and browser.

If Developers have no OpenBao access at all, hand the credential to the Admin
through a one-time secret channel, never chat or email, and the Admin runs
step 2.

Recovery codes belong in OpenBao too. The plugin maps username, password and
URIs; it has no TOTP mapping. A key such as `totp` in the KV secret would be
published as a plain-text custom field, visible to every reader, so keep a
TOTP seed out of the synced path (see
[the TOTP engine](#shared-marketing-and-social-accounts-people-and-agents)).

## 2. A secret is rotated by hand at a vendor

1. **Whoever rotates**: change the password at the vendor.
2. **Same person**: write the new value to the same KV path. With the
   write-only intake token that is a full `bao kv put` (all keys), since
   `bao kv patch` is refused for it. With read access, `bao kv patch
   secret/shared/social-acme password=...` is enough.
3. **Admin**, or nobody: `bao write -f bitwarden/sync/social-acme` pushes it
   now. Otherwise the periodic sync does, within `sync_interval` plus
   OpenBao's own tick (about a minute in the tested version).
4. **Members**: get it when their client next syncs (`bw sync`). Announce at
   most "the Acme password was rotated", never the password.

Never fix the value in Bitwarden. Developers cannot, and an Admin's edit is
overwritten by the next sync.

## 3. A secret is compromised

1. **Anyone**: report it to the Admin or security contact immediately.
2. **Admin / owner of the account**: rotate at the target system **first**,
   and end its active sessions and API tokens there. This is the step that
   revokes access.
3. **Admin**: write the new value to KV and force the sync.

   ```bash
   bao kv put secret/shared/social-acme \
       username=acme-social password='<new password>' url=https://social.example.com
   bao write -f bitwarden/sync/social-acme
   ```

4. **Admin**: confirm.

   ```bash
   bao read bitwarden/sync/social-acme    # synced true, fresh revision_date
   bao read bitwarden/status              # ok true
   ```

5. **Admin**: ask members to sync their clients.
6. **Admin**: if the leak came through a member's account or device, remove
   that member's access to the collections in Bitwarden, then rotate every
   credential in the collections they could read.
7. **Admin**: review the OpenBao audit log for the plugin mount and the KV
   path, and the vendor's access logs.
8. **Admin**: KV v2 keeps earlier versions. If policy requires it, destroy the
   compromised ones:

   ```bash
   bao kv metadata get secret/shared/social-acme       # find the versions
   bao kv destroy -versions=1,2 secret/shared/social-acme
   ```

9. **Admin**: record the incident.

The plugin cannot take back a value somebody already copied.

## 4. A vendor account is decommissioned

1. **Owner of the account**: close or disable it at the vendor, and revoke
   its API keys and sessions.
2. **Anyone**: remove the role from the configuration repository by pull
   request.
3. **Admin**: delete the role. This permanently deletes the vault item; it
   does not go to the trash.

   ```bash
   bao delete bitwarden/roles/social-acme
   ```

4. **Admin**: delete the KV secret with its version history.

   ```bash
   bao kv metadata delete secret/shared/social-acme
   ```

5. **Admin**: if the sync token's policy named that path, narrow it.
6. **Admin and Developer**: confirm. `bao list bitwarden/roles` no longer
   shows the role, and after `bw sync` the item is gone for the Developer.

Keep a record of the closure outside the vault if you need one.

## 5. CI/CD fills a secret a Developer asked for

*A Developer requests a placeholder for a future secret; a pipeline creates
the value later.*

1. **Developer**: open a pull request in the configuration repository that
   declares the future secret: KV path, role definition, target collection,
   and which pipeline will fill it. No value is involved.
2. **Admin**: review and merge. The apply step, running with Admin rights,
   creates a placeholder value and the role, and syncs:

   ```bash
   bao kv put secret/shared/ci-acme-api \
       status="pending - will be filled by the acme-provision pipeline"
   bao write bitwarden/roles/ci-acme-api \
       source_path="secret/data/shared/ci-acme-api" \
       cipher_name="Acme API key (CI)" \
       user_field=username pass_field=password url_field=url \
       collection_ids="<collection uuid>"
   bao write -f bitwarden/sync/ci-acme-api
   ```

   Developers now see an item with an empty login and a custom field
   `status: pending - ...`.

3. **Admin** (same apply step): give the pipeline an identity that can fill
   this one secret and trigger this one sync. The example uses AppRole; JWT
   or OIDC auth for your CI system serves the same purpose and was not
   tested here.

   ```bash
   bao policy write ci-acme-api - <<'EOF'
   path "secret/data/shared/ci-acme-api" {
     capabilities = ["create", "update"]
   }
   path "bitwarden/sync/ci-acme-api" {
     capabilities = ["update"]
   }
   path "sys/policies/password/ci-generated/generate" {
     capabilities = ["read"]
   }
   EOF
   bao auth enable approle
   bao write auth/approle/role/ci-acme-api \
       token_policies=ci-acme-api token_ttl=10m token_max_ttl=30m
   ```

   The pipeline gets nothing on `bitwarden/roles/*` or `bitwarden/config`.
   A role author can publish anything the mount's token can read, so role
   changes stay behind human review. The pipeline's token is also not the
   plugin's `bao_token`.

4. **Pipeline**: log in, let OpenBao generate the value from a password
   policy so that it never sits in a pipeline variable, set it at the target
   system, store it, trigger the sync.

   ```bash
   export BAO_TOKEN="$(bao write -field=token auth/approle/login \
       role_id="$ROLE_ID" secret_id="$SECRET_ID")"
   NEW="$(bao read -field=password sys/policies/password/ci-generated/generate)"
   # ... set "$NEW" at the target system ...
   bao kv put secret/shared/ci-acme-api \
       username=acme-api password="$NEW" url=https://api.acme.example.com
   bao write -f bitwarden/sync/ci-acme-api
   ```

   `bao write` exits non-zero when the sync fails, which fails the job.

5. **Developers**: after their client syncs, the same item carries the real
   value and the `status` field is gone.

Tested for the pipeline token: it can write its KV path and trigger its sync.
It cannot read its own or any other KV secret, write another KV path, write a
role, read or write `config`, sync another role, or sync all roles.

For rotation jobs:

- Order: target system first, then KV, then sync. If the KV write fails, the
  job must retry or roll the target back: the target already has the new
  value and people still see the old one.
- Never echo the value or put it in logs or artifacts.
- Periodic sync is the safety net when the explicit sync is skipped.

**Do not create the role before its KV path exists.** Observed: a manual
`sync/:name` fails with `secret not found at "..."`, nothing is published,
`status` counts the role as unsynced, and every periodic run logs
`periodic sync: failed to read source secret`. Each failed manual sync also
makes the plugin log in to the vault again on its next use. A placeholder
value avoids all of that and tells Developers what is coming.

## Shared marketing and social accounts: people and agents

Accounts that are registered by hand and used by a marketing team and by
automation or AI agents. What a given platform offers and allows changes;
check its documentation and terms.

Order of preference for access:

1. **The platform's own team or delegation features**, where it offers them.
   Each person uses their own login and no password is shared.
2. **For automation and AI agents: the platform's official API**, with app
   credentials or OAuth tokens. Store them in OpenBao KV and let the agent
   fetch them itself, with its own short-lived OpenBao identity (AppRole or
   JWT) and a policy scoped to that one path. These are machine credentials:
   do not publish them through this plugin.
3. **Only the remaining logins a person must type** (the owner login of an
   account, platforms without delegation) go from KV through this plugin into
   a collection shared read-only with the marketing team.

Do not give an agent the shared password or a Bitwarden account. An agent gets
an API token from OpenBao, with least privilege and an audit trail. Driving a
web login with a password from an agent is fragile and may breach the
platform's terms.

Rotation of such accounts is manual (scenario 2). Pick a schedule you will
actually keep, and always rotate when someone with access leaves and on
compromise (scenario 3). Browser automation for password changes is a last
resort: captchas, bot detection, lockout risk, platform terms. If you use it,
keep a person in the loop: generate the new value in OpenBao and store it as
a pending value *before* submitting the change, run a visible browser, let the
person complete captcha and MFA and confirm, verify with a fresh login, then
promote the value and sync. On failure stop and keep both values.

Two-factor material: register shared accounts on a mailbox and phone number
the organization controls, and keep recovery codes in KV outside the synced
path. OpenBao's TOTP secrets engine can hold the seed and issue codes to
authorised callers, so the seed does not live on one person's phone:

```bash
bao secrets enable totp
bao write totp/keys/social-acme \
    key=<base32 seed from the platform> issuer=Acme account_name=social@example.com
bao read totp/code/social-acme
```

Layout example: KV `secret/shared/marketing/*` synced into a collection
`marketing-social` (people, read-only); agents' API tokens under a separate
prefix such as `secret/agents/*` that the plugin's `bao_token` policy does not
cover.

## Joiners, movers, leavers

Grant access by collection membership in Bitwarden. When someone moves or
leaves, remove the membership first, then rotate every credential in the
collections they could read. (Changing membership is done in the web vault;
the end-to-end suite does not cover it.)

## Operations

- Watch `bao read bitwarden/status` and `bao list -detailed bitwarden/sync`
  for failed or stale syncs.
- Keep an OpenBao audit device enabled, so that writes to `roles/*`, `config`
  and `sync/*` are logged. In OpenBao 2.5.1 audit devices are declared in the
  server configuration; `bao audit enable` is refused.
- Review organization event logs on the Bitwarden side where the server
  provides them.
- Back up OpenBao: the sync account's master password is stored only there.
  Keep the human Admin as owner of the organization, so that it survives the
  loss of the sync account.
- Try plugin upgrades in the [end-to-end environment](e2e.md) first.

## Checklist

- [ ] Admin, sync account and Developers are separate Bitwarden accounts; a
      person owns the organization
- [ ] Sync account: PBKDF2, no two-step login, long random password stored
      only in OpenBao; *User* role with edit access to the synced collections
- [ ] `organization_id` set on `config`, `collection_ids` set on every role
- [ ] Collections hold synced items only; Developers have read-only access
- [ ] `bao_token` is read-only and limited to the synced KV paths
- [ ] Only Admins have a policy on the plugin mount
- [ ] One credential per KV path; no TOTP seeds or recovery codes in synced
      paths
- [ ] Config and roles live in a reviewed repository and can be re-applied
- [ ] Machine credentials are fetched from OpenBao directly, not published
- [ ] Rotation order: target system, KV, sync
- [ ] Leaver: remove membership, then rotate what they could read
- [ ] OpenBao audit device on; OpenBao backed up
