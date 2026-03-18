#!/usr/bin/env bash
# gen.sh — Generate a self-signed TLS certificate for the proxy.
#
# The proxy terminates TLS on behalf of clients. For local development, a
# self-signed cert is fine. Clients that complain (browsers) need to add this
# cert to their trust store, or you can pass -k / --insecure to curl.
#
# Usage:
#   cd certs && bash gen.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

openssl req \
  -x509 \
  -newkey rsa:4096 \
  -keyout proxy.key \
  -out proxy.crt \
  -days 365 \
  -nodes \
  -subj "/CN=tls-fingerprint-proxy/O=local-dev" \
  -addext "subjectAltName=DNS:localhost,DNS:proxy,IP:127.0.0.1"

echo "Generated proxy.crt and proxy.key in $(pwd)"
echo "Fingerprint: $(openssl x509 -noout -fingerprint -sha256 -in proxy.crt)"
