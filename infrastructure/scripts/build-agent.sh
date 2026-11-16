#!/usr/bin/env bash
# Tests and cross-compiles the agent inside the official Go container (no local Go needed).
# Output: agent/go-security-agent/bin/shsc-agent-<os>-<arch>[.exe] + SHA256SUMS
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${SHSC_AGENT_VERSION:-0.0.0-dev}"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

MSYS_NO_PATHCONV=1 docker run --rm \
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
    cd bin && sha256sum shsc-agent-* > SHA256SUMS && ls -l
  '
