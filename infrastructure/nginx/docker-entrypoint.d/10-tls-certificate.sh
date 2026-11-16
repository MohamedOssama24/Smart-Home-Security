#!/bin/sh
# Ensures a TLS certificate exists at /etc/nginx/tls/{fullchain,privkey}.pem.
# Production: mount real certificates (e.g. Let's Encrypt) and leave SHSC_TLS_SELF_SIGNED=false.
# Development: SHSC_TLS_SELF_SIGNED=true creates a self-signed certificate for SHSC_PUBLIC_HOST.
set -eu

CERT_DIR=/etc/nginx/tls
CERT="$CERT_DIR/fullchain.pem"
KEY="$CERT_DIR/privkey.pem"

if [ -s "$CERT" ] && [ -s "$KEY" ]; then
    echo "shsc: using TLS certificate from $CERT_DIR"
    exit 0
fi

if [ "${SHSC_TLS_SELF_SIGNED:-false}" != "true" ]; then
    echo "shsc: ERROR no TLS certificate in $CERT_DIR and SHSC_TLS_SELF_SIGNED is not true" >&2
    exit 1
fi

HOST="${SHSC_PUBLIC_HOST:-localhost}"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1" \
    -keyout "$KEY" -out "$CERT" 2>/dev/null
chmod 600 "$KEY"
echo "shsc: WARNING generated a self-signed development certificate for $HOST (valid 30 days)"
