#!/usr/bin/env bash
# Logical backup of the PostgreSQL database (pg_dump custom format) with retention.
# Usage: infrastructure/scripts/backup-db.sh            (reads .env from the repository root)
# Restore: docker compose exec -T postgres pg_restore -U "$POSTGRES_SUPERUSER" -d "$SHSC_DB_NAME" --clean < file.dump
# NOTE: off-site, encrypted backup storage is part of Milestone 18 (hardening).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  echo "backup: .env not found in $ROOT" >&2
  exit 1
fi
set -a; . ./.env; set +a

BACKUP_DIR="${SHSC_BACKUP_DIR:-./backups}"
RETENTION_DAYS="${SHSC_BACKUP_RETENTION_DAYS:-14}"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true

FILE="$BACKUP_DIR/shsc-$(date -u +%Y%m%dT%H%M%SZ).dump"
TMP="$FILE.partial"

docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_SUPERUSER" -d "$SHSC_DB_NAME" --format=custom > "$TMP"

# A custom-format dump starts with the "PGDMP" magic header
if [ "$(head -c 5 "$TMP")" != "PGDMP" ]; then
  echo "backup: dump is invalid, keeping $TMP for inspection" >&2
  exit 1
fi
mv "$TMP" "$FILE"
echo "backup: written $FILE ($(wc -c < "$FILE") bytes)"

find "$BACKUP_DIR" -name 'shsc-*.dump' -type f -mtime +"$RETENTION_DAYS" -print -delete \
  | sed 's/^/backup: removed old /'
