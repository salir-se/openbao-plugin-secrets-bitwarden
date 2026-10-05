#!/usr/bin/env bash
# Developer Certificate of Origin check: every non-merge commit in a range must
# carry a `Signed-off-by:` trailer naming its author or committer.
#
# Usage: scripts/check-dco.sh <base-rev> <head-rev>
# Example: scripts/check-dco.sh main HEAD
# CI runs it on every pull request with the PR's base and head commits.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <base-rev> <head-rev>" >&2
  exit 2
fi

base="$1"
head="$2"

lower() { tr '[:upper:]' '[:lower:]'; }

# GitHub Actions turns `::error::` lines into annotations; elsewhere print plainly.
error() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error::$*"
  else
    echo "error: $*" >&2
  fi
}

failed=0
checked=0
for sha in $(git rev-list --no-merges "${base}..${head}"); do
  checked=$((checked + 1))
  author="$(git show -s --format='%an <%ae>' "$sha" | lower)"
  committer="$(git show -s --format='%cn <%ce>' "$sha" | lower)"
  signoffs="$(git show -s --format='%(trailers:key=Signed-off-by,valueonly,unfold)' "$sha" | sed '/^[[:space:]]*$/d' | lower)"
  subject="$(git show -s --format='%s' "$sha")"

  ok=0
  if printf '%s\n' "$signoffs" | grep -Fxq -e "$author" -e "$committer"; then
    ok=1
  # Dependabot authors commits as
  #   dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>
  # but signs them off as
  #   dependabot[bot] <support@github.com>
  # so the trailer never matches the author. Accept exactly that pair.
  elif [ "$author" = 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>' ] &&
    printf '%s\n' "$signoffs" | grep -Fxq 'dependabot[bot] <support@github.com>'; then
    ok=1
  fi

  if [ "$ok" -eq 1 ]; then
    echo "ok      ${sha:0:12} $subject"
  else
    failed=1
    error "Commit ${sha:0:12} (\"$subject\") has no Signed-off-by trailer matching its author or committer."
    echo "MISSING ${sha:0:12} $subject"
    echo "        author:     $author"
    echo "        committer:  $committer"
    echo "        sign-offs:  ${signoffs:-<none>}"
  fi
done

echo "Checked $checked commit(s)."
if [ "$failed" -ne 0 ]; then
  echo
  echo "Add the sign-off with 'git commit --amend --signoff' (last commit) or"
  echo "'git rebase --signoff <base>' (whole branch), then force-push."
  echo "'mise install' registers a commit-msg hook that adds it to future commits."
  echo "The name and email in the trailer must match the commit author."
  echo "See CONTRIBUTING.md and https://developercertificate.org/"
  exit 1
fi
