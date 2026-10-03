#!/usr/bin/env bash
# Writes a throwaway CA and a server certificate for Vaultwarden into the
# compose volumes. Nothing here is ever committed: the files exist only in the
# `tls` and `state` volumes and disappear with `make e2e-down`.
#
#   /state/ca.crt       CA certificate, for everything that must trust it
#   /tls/server.crt     server certificate (vaultwarden, localhost, 127.0.0.1)
#   /tls/server.key     its private key, mounted into Vaultwarden only
#
# The CA private key is deleted once the server certificate is signed.
set -euo pipefail

DAYS=30

if [ -s /state/ca.crt ] && [ -s /tls/server.crt ] && [ -s /tls/server.key ] &&
  openssl verify -CAfile /state/ca.crt /tls/server.crt >/dev/null 2>&1 &&
  openssl x509 -in /tls/server.crt -noout -checkend 86400 >/dev/null; then
  echo "[certs] existing certificate is still valid, nothing to do"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/ca.key" -out "$work/ca.crt" -days "$DAYS" \
  -subj "/O=openbao-plugin-secrets-bitwarden e2e/CN=Throwaway e2e CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/server.key" -out "$work/server.csr" \
  -subj "/O=openbao-plugin-secrets-bitwarden e2e/CN=vaultwarden" 2>/dev/null

cat >"$work/server.ext" <<'EXT'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:vaultwarden,DNS:localhost,IP:127.0.0.1
EXT

openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -days "$DAYS" -extfile "$work/server.ext" -out "$work/server.crt" 2>/dev/null

install -m 0644 "$work/server.crt" /tls/server.crt
install -m 0600 "$work/server.key" /tls/server.key
install -m 0644 "$work/ca.crt" /state/ca.crt

echo "[certs] wrote a new CA and server certificate, valid for $DAYS days"
openssl x509 -in /tls/server.crt -noout -subject -issuer -ext subjectAltName
