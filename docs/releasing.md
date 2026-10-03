# Releasing

For maintainers. The process is modelled on OpenBao's
[release policy](https://openbao.org/community/policies/release/), scaled down
to a single-plugin repository.

Releases are published only by GitHub Actions. Do not build release artifacts
on a workstation and upload them by hand.

## Versioning

The project follows [Semantic Versioning](https://semver.org/).

| Bump | When |
|------|------|
| Major | An incompatible change to an API path or field, or to stored state (config or roles written by an older version no longer work). Applies once the project is past 1.0 |
| Minor | New functionality that is backward compatible. **While the version is 0.x, breaking changes also bump the minor** and are listed under "Changes" in the changelog |
| Patch | Bug and security fixes only |

Pre-releases are named `vX.Y.Z-beta1`, `vX.Y.Z-rc1` and so on. They are
published as GitHub pre-releases and are not tagged `latest`.

## Branches

- New features go to `main`.
- After the first release of a minor series (pre-releases included), create a
  `release/<major.minor>` branch from the tag, for example `release/0.1`.
- Bug and security fixes land on `main` and are backported to the release
  branch that needs them.
- Anything fixed on a release branch first must be forward-ported to `main`,
  including its changelog entry.

Fixes are provided for the latest minor series only, unless a release
announcement states otherwise. See [SECURITY.md](../SECURITY.md#supported-versions).

## What the release workflow does

Pushing a tag that matches `v*` starts `.github/workflows/release.yml`:

1. The unit tests with the coverage gate and the integration tests run. If
   either fails, nothing is published.
2. GoReleaser builds static binaries for linux and darwin on amd64 and arm64,
   publishes each as a bare binary and as a `.tar.gz` archive named
   `openbao-plugin-secrets-bitwarden_<version>_<os>_<arch>`, and writes
   `checksums.txt` with their SHA-256 sums.
3. A build-provenance attestation is created for every file listed in
   `checksums.txt`.

The same workflow can be started manually from the Actions tab. That is a
snapshot dry run: it builds everything and attaches the result to the workflow
run without publishing.

## Checklist

### Before the release

- [ ] Decide the version: major, minor or patch, and final or pre-release.
- [ ] Confirm the features and fixes meant for this release are merged, and CI
      is green on the branch you release from (`main`, or `release/<major.minor>`
      for a patch).
- [ ] Update the Go `toolchain` directive in `go.mod` to the current Go patch
      release.
- [ ] Update every dependency with a known vulnerability. `govulncheck ./...`
      must be clean. Do larger dependency upgrades early in the cycle, not on
      release day.
- [ ] Run the snapshot dry run from the Actions tab and check that all
      artifacts build.
- [ ] Update `CHANGELOG.md`: move the entries under `Unreleased` to a new
      section for the version with today's date, keep the category headings
      (Features, Improvements, Changes, Deprecations, Bugs), and update the
      comparison links at the bottom. Merge that change.
- [ ] For a patch released from a release branch, forward-port the changelog
      section to `main`.

### Release

- [ ] Tag the merge commit and push the tag:

  ```bash
  git checkout main && git pull        # or release/<major.minor>
  git tag -a v0.1.0 -m "v0.1.0"
  git push origin v0.1.0
  ```

- [ ] Watch the release workflow until it finishes.

### After the workflow finishes

- [ ] The release page lists every platform, the archives and `checksums.txt`.
      A pre-release is marked as such.
- [ ] Spot-check a downloaded binary against `checksums.txt`:

  ```bash
  sha256sum --ignore-missing -c checksums.txt
  ```

- [ ] Verify the provenance attestation of that binary:

  ```bash
  gh attestation verify openbao-plugin-secrets-bitwarden_<version>_<os>_<arch> \
      --repo salir-se/openbao-plugin-secrets-bitwarden
  ```

- [ ] Register the binary in a throwaway OpenBao and confirm the plugin starts.
- [ ] Container image: see the next section.
- [ ] Publish any security advisory fixed by this release.
- [ ] For the first release of a new minor series, create the
      `release/<major.minor>` branch.

### Container image checks

The release workflow pushes a multi-arch image to
`ghcr.io/salir-se/openbao-plugin-secrets-bitwarden`, signs it by digest with
keyless cosign and verifies that signature before it finishes. Repeat the
check from outside the workflow:

- [ ] Confirm the image for the tag exists and that a pre-release did not move
      `latest`.
- [ ] Verify the cosign signature of the image and of `checksums.txt`:

  ```bash
  TAG=v<version>
  IMAGE=ghcr.io/salir-se/openbao-plugin-secrets-bitwarden
  IDENTITY="https://github.com/salir-se/openbao-plugin-secrets-bitwarden/.github/workflows/release.yml@refs/tags/${TAG}"
  DIGEST=$(docker buildx imagetools inspect "$IMAGE:$TAG" --format '{{json .Manifest.Digest}}' | tr -d '"')

  cosign verify "$IMAGE@$DIGEST" \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

  cosign verify-blob checksums.txt \
      --bundle checksums.txt.sigstore.json \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- [ ] Confirm OpenBao can load the plugin from the image (declarative `plugin`
      stanza, see the README).
- [ ] After the first release, set the GHCR package visibility to public;
      otherwise OpenBao's auto-download needs registry credentials.

## If a release is wrong

Do not move or reuse a published tag. Users register the plugin by SHA-256, so
replacing artifacts under an existing version silently breaks them. Fix the
problem and publish a new patch version.
