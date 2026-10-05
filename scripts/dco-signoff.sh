#!/usr/bin/env bash
# Git commit-msg hook: add the DCO `Signed-off-by:` trailer when the message
# does not already carry one for the committer. The effect is the same as
# passing `--signoff` on every `git commit`, which CI's DCO check requires.
#
# Wired up through lefthook.yml; `mise install` (or `mise run hooks`) installs
# it into this clone. Skip it for one commit with `git commit --no-verify`.
#
# Usage: scripts/dco-signoff.sh <commit-message-file>
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <commit-message-file>" >&2
  exit 2
fi
msg_file="$1"

# `git var` yields "Name <email> <timestamp> <tz>"; keep only the identity.
ident="$(git var GIT_COMMITTER_IDENT | sed -E 's/ [0-9]+ [-+][0-9]{4}$//')"

# addIfDifferent: keep an existing sign-off for this identity; add ours next
# to someone else's (a cherry-picked commit, for example).
git interpret-trailers --in-place --if-exists addIfDifferent \
  --trailer "Signed-off-by: $ident" "$msg_file"
