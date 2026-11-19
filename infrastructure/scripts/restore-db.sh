#!/usr/bin/env bash
# Restore of a backup made by backup-db.sh (M18).
#
#   restore-db.sh verify <file.dump>   restores into a THROWAWAY postgres container (the running
#                                      database is not touched) and checks schema and row counts
#   restore-db.sh live   <file.dump>   restores into the running database (--clean): stop the
#                                      backend first; asks to type the database name to confirm
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
MODE="${1:-}"
DUMP="${2:-}"
if [ -z "$MODE" ] || [ ! -f "$DUMP" ]; then
  echo "usage: restore-db.sh verify|live <file.dump>" >&2
  exit 2
fi
if [ "$(head -c 5 "$DUMP")" != "PGDMP" ]; then
  echo "restore: $DUMP is not a pg_dump custom-format file" >&2
  exit 1
fi
set -a; . ./.env; set +a

case "$MODE" in
  verify)
    NAME="shsc-restore-verify-$$"
    PASS="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
    trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
    docker run -d --name "$NAME" --network none -e POSTGRES_PASSWORD="$PASS" postgres:18-alpine >/dev/null
    for _ in $(seq 1 60); do
      docker exec "$NAME" pg_isready -U postgres -q 2>/dev/null && break
      sleep 1
    done
    docker exec -i "$NAME" sh -c 'cat > /tmp/d.dump' < "$DUMP"
    # create the roles referenced by ownership/GRANTs in the dump (roles are not part of pg_dump)
    ROLES="$(docker exec "$NAME" pg_restore -f - --schema-only /tmp/d.dump \
      | grep -oE '(OWNER TO|TO|FROM) "?[a-z_][a-z0-9_]*' | awk '{print $NF}' | tr -d '"' | sort -u)"
    for role in $ROLES; do
      [ "$role" = postgres ] || \
        docker exec "$NAME" psql -U postgres -qc "CREATE ROLE \"$role\"" >/dev/null 2>&1 || true
    done
    docker exec "$NAME" createdb -U postgres "$SHSC_DB_NAME"
    docker exec "$NAME" pg_restore -U postgres -d "$SHSC_DB_NAME" --exit-on-error /tmp/d.dump
    # application objects live in the "shsc" schema (Flyway default schema)
    docker exec "$NAME" psql -U postgres -d "$SHSC_DB_NAME" -At -v ON_ERROR_STOP=1 -c "
      SET search_path = shsc;
      SELECT 'flyway_last_version=' || max(version::int) FROM flyway_schema_history WHERE success AND version IS NOT NULL;
      SELECT 'flyway_failed=' || count(*) FROM flyway_schema_history WHERE NOT success;
      SELECT 'tables=' || count(*) FROM information_schema.tables WHERE table_schema = 'shsc';
      SELECT 'rls_tables=' || count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'shsc' AND c.relkind = 'r' AND c.relrowsecurity;
      SELECT 'tenants=' || count(*) FROM tenants;
      SELECT 'users=' || count(*) FROM users;"
    echo "restore verify: OK ($DUMP restored into a throwaway container, removed on exit)"
    ;;
  live)
    printf 'Restore %s into the RUNNING database "%s" (existing data replaced). Type the database name: ' \
      "$DUMP" "$SHSC_DB_NAME"
    read -r answer
    [ "$answer" = "$SHSC_DB_NAME" ] || { echo "restore: cancelled" >&2; exit 1; }
    docker compose exec -T postgres pg_restore -U "$POSTGRES_SUPERUSER" -d "$SHSC_DB_NAME" \
      --clean --if-exists --exit-on-error < "$DUMP"
    echo "restore: done, start the backend again (Flyway validates the schema at startup)"
    ;;
  *)
    echo "usage: restore-db.sh verify|live <file.dump>" >&2
    exit 2
    ;;
esac
