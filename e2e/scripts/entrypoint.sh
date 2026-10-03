#!/usr/bin/env bash
# Entrypoint of the tools image. Trusts the environment's private CA, points
# both CLIs at the environment, then runs the given command.
set -euo pipefail

# System trust store (curl, the bootstrap program). bw reads the CA from
# NODE_EXTRA_CA_CERTS, set in the image.
if [ -s /state/ca.crt ]; then
  cp /state/ca.crt /usr/local/share/ca-certificates/e2e-ca.crt
  update-ca-certificates >/dev/null 2>&1
fi

# bao: BAO_ADDR comes from compose; the token is the dev root token.
if [ -n "${E2E_BAO_ROOT_TOKEN:-}" ]; then
  export BAO_TOKEN="${BAO_TOKEN:-$E2E_BAO_ROOT_TOKEN}"
fi

# IDs produced by setup: E2E_ORG_ID, E2E_COLLECTION_ID, ...
if [ -s /state/e2e.env ]; then
  set -a
  # shellcheck disable=SC1091 # written by setup.sh at run time
  . /state/e2e.env
  set +a
fi

# bw: use this environment's server instead of bitwarden.com.
if [ -n "${E2E_VW_URL:-}" ] && [ -s /state/ca.crt ]; then
  bw config server "$E2E_VW_URL" >/dev/null 2>&1 || {
    echo "bw config server $E2E_VW_URL failed" >&2
    exit 1
  }
fi

export PATH="/e2e:$PATH"

if [ -t 0 ] && [ "${1:-}" = "bash" ]; then
  cat <<BANNER
e2e tools: bao -> ${BAO_ADDR:-?} (root token), bw -> ${E2E_VW_URL:-?}

  bao read bitwarden/status
  bao list bitwarden/roles
  export BW_SESSION="\$(bw-session.sh developer)"  # or: admin, sync
  bw list items --organizationid "\$E2E_ORG_ID"

Organization: ${E2E_ORG_ID:-<run setup first>}
Collection:   ${E2E_COLLECTION_ID:-<run setup first>}
BANNER
fi

exec "$@"
