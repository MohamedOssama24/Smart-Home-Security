#!/bin/sh
# Generates the Ed25519 private key that signs the scan jobs sent to the agents and prints
# it as one base64 line (PKCS#8 DER), ready for SHSC_JOB_SIGNING_KEY in .env.
#
#   sh infrastructure/scripts/generate-job-signing-key.sh
#
# The key never touches the disk. The backend derives the public key at startup and gives it
# to each agent at enrollment; agents pin it and refuse jobs not signed with it
# (docs/03-AGENT-PROTOCOL.md §6). Changing the key therefore requires enrolling the agents
# again: keep it in the secret store and back it up with the other secrets.
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | openssl base64 -A
echo
