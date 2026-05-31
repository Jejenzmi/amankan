#!/usr/bin/env bash
# Generate self-signed TLS certs for LOCAL / internal production trials.
# For real production use certificates from your CA (or cert-manager / Let's Encrypt).
#
#   ./scripts/gen-certs.sh            # writes to deploy/certs/
#
# Produces:
#   deploy/certs/api.crt   deploy/certs/api.key      (Amankan API HTTPS)
#   deploy/certs/server.crt deploy/certs/server.key  (PostgreSQL TLS)
set -euo pipefail

OUT="${1:-deploy/certs}"
API_CN="${API_CN:-localhost}"
DB_CN="${DB_CN:-postgres}"
mkdir -p "$OUT"

gen() { # <name> <CN>
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$OUT/$1.key" -out "$OUT/$1.crt" \
    -subj "/CN=$2" -addext "subjectAltName=DNS:$2,DNS:localhost,IP:127.0.0.1" 2>/dev/null
  chmod 600 "$OUT/$1.key"
}

gen api "$API_CN"
gen server "$DB_CN"

# PostgreSQL requires the server key to be owned by the postgres uid (999 in the
# official image) and mode 600, or it refuses to start with ssl=on.
chmod 600 "$OUT/server.key"
echo "certs written to $OUT/"
echo "NOTE: for the postgres container, ensure server.key is owned by uid 999:"
echo "      sudo chown 999:999 $OUT/server.key $OUT/server.crt"
