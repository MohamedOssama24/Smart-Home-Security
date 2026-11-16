#!/bin/sh
# Generates the ES256 (P-256) private key that signs the API access tokens and prints it
# as one base64 line (PKCS#8 DER), ready for SHSC_JWT_PRIVATE_KEY in .env.
#
#   sh infrastructure/scripts/generate-jwt-key.sh
#
# The key never touches the disk. The public key is derived by the backend at startup.
# Rotating it invalidates the access tokens already issued (they fail signature checks);
# refresh tokens are opaque and stay valid, so the dashboard silently refreshes and
# sessions continue.
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -inform DER -outform DER \
  | openssl base64 -A
echo
