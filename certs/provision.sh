#!/usr/bin/env bash
# provision.sh — Obtain a Let's Encrypt certificate via certbot (standalone mode).
#
# Certbot starts a temporary HTTP server on port 80 to answer the ACME
# challenge. The proxy only binds port 443, so there is no conflict.
#
# Prerequisites:
#   - Docker installed and running on this machine
#   - Port 80 reachable from the internet (open in your firewall/VPS panel)
#   - DNS A record for DOMAIN already pointing at this server's IP
#     (Let's Encrypt will do a DNS lookup — propagation must be complete)
#
# Usage:
#   bash certs/provision.sh <domain> <email>
#
# Example:
#   bash certs/provision.sh fingerprint.example.com me@example.com
#
# Certs are written to:
#   certs/letsencrypt/live/<domain>/fullchain.pem  (certificate + chain)
#   certs/letsencrypt/live/<domain>/privkey.pem    (private key)

set -euo pipefail

DOMAIN="${1:?Usage: provision.sh <domain> <email>}"
EMAIL="${2:?Usage: provision.sh <domain> <email>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LETSENCRYPT_DIR="$SCRIPT_DIR/letsencrypt"

mkdir -p "$LETSENCRYPT_DIR"

echo "Requesting Let's Encrypt certificate for: $DOMAIN"
echo "Email: $EMAIL"
echo "Cert directory: $LETSENCRYPT_DIR"
echo ""

docker run --rm \
  -p 80:80 \
  -v "$LETSENCRYPT_DIR:/etc/letsencrypt" \
  certbot/certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN"

echo ""
echo "Certificate obtained successfully."
echo "  Cert: $LETSENCRYPT_DIR/live/$DOMAIN/fullchain.pem"
echo "  Key:  $LETSENCRYPT_DIR/live/$DOMAIN/privkey.pem"
echo ""
echo "Next step: make up-prod DOMAIN=$DOMAIN"
