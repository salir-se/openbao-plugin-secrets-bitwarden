# Working in this repository

- Every commit needs a DCO `Signed-off-by` trailer for its author or
  committer. The `DCO sign-off` CI job rejects pull requests without it.
  Commit with `git commit --signoff`, or run `mise install` once so the
  lefthook `commit-msg` hook adds the trailer. Check with `mise run dco`.
- Tools and tasks come from `mise.toml`; there is no Makefile. Use
  `mise run <task>` (`mise tasks` lists them). CI only calls those tasks and
  the scripts in `scripts/`, so put new checks there, not inline in workflows.
- Before pushing: `mise run lint` and `mise run cover` (coverage gate 95%).
- Read CONTRIBUTING.md for the DCO, licence and AI-disclosure rules.
