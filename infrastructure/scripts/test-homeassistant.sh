#!/usr/bin/env sh
# Milestone 15 - integration test of the agent with a REAL Home Assistant in a container
# (docs/24-INTEGRATIONS.md §6). Everything is local and throwaway:
#  - Home Assistant 2026.11.2 with the "demo" integration ([MOCK] devices), port bound to 127.0.0.1;
#  - a test owner is created with the onboarding API (random password, never printed);
#  - the agent test reads the inventory with the resulting access token (never printed);
#  - container, network and configuration are removed at the end.
# Usage: sh infrastructure/scripts/test-homeassistant.sh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HA_IMAGE="ghcr.io/home-assistant/home-assistant:2026.11.2"
NAME="shsc-ha-test"
PORT=18123
WORK="$(mktemp -d)"
CLIENT_ID="http://127.0.0.1:${PORT}/"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cat > "$WORK/configuration.yaml" <<'EOF'
homeassistant:
  name: "[MOCK] SHSC test"
  unit_system: metric
  time_zone: UTC
  country: IT
  latitude: 0
  longitude: 0
  elevation: 0
api:
onboarding:
demo:
EOF

docker network create "$NAME" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$NAME" --network "$NAME" -p "127.0.0.1:${PORT}:8123" \
  -v "$WORK:/config" "$HA_IMAGE" >/dev/null

echo "waiting for Home Assistant..."
i=0
until curl -fsS "http://127.0.0.1:${PORT}/api/onboarding" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 180 ]; then echo "Home Assistant did not start"; docker logs --tail 50 "$NAME"; exit 1; fi
  sleep 2
done

# test owner (random password, never printed) -> authorization code -> access token
PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CODE="$(curl -fsS -X POST "http://127.0.0.1:${PORT}/api/onboarding/users" -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"${CLIENT_ID}\",\"name\":\"MOCK owner\",\"username\":\"mock-owner\",\"password\":\"${PASSWORD}\",\"language\":\"en\"}" \
  | sed -n 's/.*"auth_code": *"\([^"]*\)".*/\1/p')"
TOKEN="$(curl -fsS -X POST "http://127.0.0.1:${PORT}/auth/token" \
  --data-urlencode grant_type=authorization_code --data-urlencode "code=${CODE}" \
  --data-urlencode "client_id=${CLIENT_ID}" | sed -n 's/.*"access_token": *"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN" ] || { echo "cannot obtain the test token"; exit 1; }

# the demo integration creates its devices a few seconds after start
sleep 10
HA_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
MSYS_NO_PATHCONV=1 docker run --rm --network "$NAME" \
  -v "$ROOT/agent/go-security-agent:/src" -v shsc-go-cache:/root/.cache -v shsc-go-mod:/go/pkg/mod -w /src \
  -e CGO_ENABLED=0 -e SHSC_HA_TEST_URL="http://${HA_IP}:8123" -e SHSC_HA_TEST_TOKEN="$TOKEN" \
  golang:1.27-alpine go test -count=1 -v -run TestRealHomeAssistant ./internal/homeassistant/
