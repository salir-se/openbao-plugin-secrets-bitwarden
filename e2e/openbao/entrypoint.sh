#!/bin/sh
# Entrypoint of the e2e OpenBao container. Runs as root, then hands over to the
# image's own entrypoint, which drops to the openbao user.
set -eu

# The plugin has no CA option: it verifies the Bitwarden server against the
# system trust store. Installing the private CA there is the supported way to
# use a server certificate that is not publicly trusted.
cp /state/ca.crt /usr/local/share/ca-certificates/e2e-ca.crt
update-ca-certificates

# What `bao plugin register -sha256=...` needs. Published for the setup
# container, which has no access to this filesystem.
sha256sum /openbao/plugins/openbao-plugin-secrets-bitwarden | cut -d' ' -f1 >/state/plugin.sha256

exec docker-entrypoint.sh "$@"
