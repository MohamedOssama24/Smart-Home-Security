#!/usr/bin/env bash
# Runs the backend test suite inside a JDK 21 / Maven container, so no local Java setup is needed.
# Testcontainers talks to the host Docker daemon through the mounted socket.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

MSYS_NO_PATHCONV=1 docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$ROOT":/workspace \
  -v shsc-maven-cache:/root/.m2 \
  -w /workspace/backend/spring-boot-api \
  -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal \
  --add-host=host.docker.internal:host-gateway \
  maven:3.9-eclipse-temurin-21 \
  mvn -B verify "$@"
