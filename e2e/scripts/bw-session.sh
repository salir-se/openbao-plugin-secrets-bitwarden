#!/usr/bin/env bash
# Logs the Bitwarden CLI in as one of the fixture accounts and prints the
# session key. bw holds one login at a time, so any other login is dropped.
#
#   export BW_SESSION="$(bw-session.sh developer)"    # or: admin, sync
set -euo pipefail

case "${1:-}" in
  admin)     email="$E2E_ADMIN_EMAIL";  password_var=E2E_ADMIN_PASSWORD ;;
  sync)      email="$E2E_SYNC_EMAIL";   password_var=E2E_SYNC_PASSWORD ;;
  developer) email="$E2E_DEVELOPER_EMAIL"; password_var=E2E_DEVELOPER_PASSWORD ;;
  *) echo "usage: $0 admin|sync|developer" >&2; exit 2 ;;
esac

bw logout >/dev/null 2>&1 || true
bw login "$email" --passwordenv "$password_var" --raw
