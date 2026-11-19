#!/usr/bin/env bash
# Tests and cross-compiles the agent inside the official Go container (no local Go needed).
# Output: agent/go-security-agent/bin/shsc-agent-<os>-<arch>[.exe] + SHA256SUMS
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${SHSC_AGENT_VERSION:-0.0.0-dev}"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Release signing (M18, ADR-073): SHSC_RELEASE_KEY_FILE = Ed25519 private key created with
#   shsc-release-sign keygen release.key release.pub   (keep release.key offline, never in git)
# When set, bin/SHA256SUMS.sig is written; users verify with shsc-release-sign verify release.pub SHA256SUMS
KEY_MOUNT=()
if [ -n "${SHSC_RELEASE_KEY_FILE:-}" ]; then
  KEY_PATH="$(cd "$(dirname "$SHSC_RELEASE_KEY_FILE")" && pwd)/$(basename "$SHSC_RELEASE_KEY_FILE")"
  [ -f "$KEY_PATH" ] || { echo "build-agent: $SHSC_RELEASE_KEY_FILE not found" >&2; exit 1; }
  # Git Bash on Windows: give Docker a Windows path (e.g. /tmp is not visible to Docker Desktop)
  command -v cygpath >/dev/null 2>&1 && KEY_PATH="$(cygpath -m "$KEY_PATH")"
  KEY_MOUNT=(-v "$KEY_PATH":/keys/release.key:ro)
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  "${KEY_MOUNT[@]}" \
  -v "$ROOT/agent/go-security-agent":/src \
  -v shsc-go-cache:/root/.cache \
  -w /src \
  -e CGO_ENABLED=0 \
  -e VERSION="$VERSION" -e COMMIT="$COMMIT" -e DATE="$DATE" \
  golang:1.27-alpine sh -euc '
    go vet ./...
    go test ./...
    rm -rf bin && mkdir -p bin
    PKG=shsc/agent/internal/buildinfo
    LDFLAGS="-s -w -X $PKG.version=$VERSION -X $PKG.commit=$COMMIT -X $PKG.date=$DATE"
    for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64; do
      os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "bin/shsc-agent-$os-$arch$ext" ./cmd/shsc-agent
    done
    for target in windows/amd64 linux/amd64 darwin/arm64; do
      os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "bin/shsc-release-sign-$os-$arch$ext" ./cmd/shsc-release-sign
    done
    cd bin && sha256sum shsc-agent-* shsc-release-sign-* > SHA256SUMS
    if [ -f /keys/release.key ]; then
      go run ../cmd/shsc-release-sign sign /keys/release.key SHA256SUMS
      echo "SHA256SUMS signed"
    else
      echo "WARNING: SHSC_RELEASE_KEY_FILE not set, SHA256SUMS is NOT signed"
    fi
    ls -l
  '
