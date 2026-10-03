# Plugin image for OpenBao's OCI-based plugin distribution
# (https://openbao.org/docs/configuration/plugins). Same layout as the images
# from openbao/openbao-plugins: a scratch image holding only the static plugin
# binary at the root, named by ENTRYPOINT, which is how OpenBao locates it.
#
# Built by GoReleaser (dockers_v2 in .goreleaser.yaml). The build context holds
# the prebuilt binaries as <os>/<arch>/openbao-plugin-secrets-bitwarden, so
# nothing is compiled here.
FROM scratch
ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/openbao-plugin-secrets-bitwarden /openbao-plugin-secrets-bitwarden

ENTRYPOINT ["/openbao-plugin-secrets-bitwarden"]
