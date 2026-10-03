# OpenBao with the plugin from this checkout, for the e2e environment
# (e2e/compose.yaml). Build context is the repository root.

# Stage 1: build the plugin the way releases are built: static, no cgo.
# The Go version must match the `toolchain` line in go.mod.
FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=e2e' \
      -o /out/openbao-plugin-secrets-bitwarden ./cmd/openbao-plugin-secrets-bitwarden

# Stage 2: the official OpenBao image plus the plugin binary in a plugin
# directory. The binary is registered by e2e/scripts/setup.sh with
# `bao plugin register -sha256=...`, as an operator would.
FROM openbao/openbao:2.5.1@sha256:87d715029a47328172774638cabfeb04d5b356678d660621b796b6a671f93581

# update-ca-certificates, used by the entrypoint to trust the private CA.
RUN apk add --no-cache ca-certificates

COPY --from=build --chown=openbao:openbao --chmod=0755 \
     /out/openbao-plugin-secrets-bitwarden /openbao/plugins/openbao-plugin-secrets-bitwarden
COPY --chown=openbao:openbao e2e/openbao/plugins.hcl /openbao/config/plugins.hcl
COPY --chmod=0755 e2e/openbao/entrypoint.sh /usr/local/bin/e2e-entrypoint.sh

ENTRYPOINT ["e2e-entrypoint.sh"]
CMD ["server", "-dev", "-dev-no-store-token"]
