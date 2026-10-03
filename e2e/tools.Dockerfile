# Tools image of the e2e environment (e2e/compose.yaml): the OpenBao CLI, the
# Bitwarden CLI, the bootstrap program and the e2e scripts. Build context is
# the repository root.

# The bootstrap program creates the fixture accounts and organization.
FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY e2e/bootstrap ./e2e/bootstrap
RUN CGO_ENABLED=0 go build -trimpath -tags e2e -ldflags='-s -w' -o /out/e2e-bootstrap ./e2e/bootstrap

# Source of the `bao` binary: the same OpenBao version the server runs.
FROM openbao/openbao:2.5.1@sha256:87d715029a47328172774638cabfeb04d5b356678d660621b796b6a671f93581 AS openbao

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq openssl unzip \
 && rm -rf /var/lib/apt/lists/*

# Bitwarden CLI, pinned by version and checksum. The "oss" build is the one
# without the code under the Bitwarden License.
ARG TARGETARCH
ARG BW_VERSION=2026.2.0
ARG BW_SHA256_AMD64=41d254d428c3226ecfefe5d49132ed869758507fa9c9c4123ccea011fdb875bc
ARG BW_SHA256_ARM64=28ec12b9389e6eff0253ce0dee1eec61d528fd0d354466b9b7c7b1cad3649b9d
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) asset="bw-oss-linux-${BW_VERSION}.zip"; sum="${BW_SHA256_AMD64}" ;; \
      arm64) asset="bw-oss-linux-arm64-${BW_VERSION}.zip"; sum="${BW_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/${asset}"; \
    echo "${sum}  /tmp/bw.zip" | sha256sum -c -; \
    unzip -q /tmp/bw.zip bw -d /usr/local/bin; \
    chmod 0755 /usr/local/bin/bw; \
    rm /tmp/bw.zip

COPY --from=openbao /bin/bao /usr/local/bin/bao
COPY --from=build /out/e2e-bootstrap /usr/local/bin/e2e-bootstrap
COPY --chmod=0755 e2e/scripts/ /e2e/

# The private CA of the environment. bw is a Node.js program and reads extra
# CAs from NODE_EXTRA_CA_CERTS; everything else uses the system trust store,
# which the entrypoint updates.
ENV NODE_EXTRA_CA_CERTS=/state/ca.crt \
    BITWARDENCLI_APPDATA_DIR=/root/.config/bitwarden-cli

WORKDIR /root
ENTRYPOINT ["/e2e/entrypoint.sh"]
CMD ["bash"]
