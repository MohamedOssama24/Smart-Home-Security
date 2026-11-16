#!/bin/sh
# Runs once, on first initialisation of the PostgreSQL data volume.
# Creates the two application roles (ADR-004):
#   - migrator: owns schema "shsc", runs Flyway migrations (DDL)
#   - app:      runtime role used by the API, DML only, cannot bypass RLS
set -eu

: "${SHSC_DB_MIGRATOR_USER:?SHSC_DB_MIGRATOR_USER is required}"
: "${SHSC_DB_MIGRATOR_PASSWORD:?SHSC_DB_MIGRATOR_PASSWORD is required}"
: "${SHSC_DB_APP_USER:?SHSC_DB_APP_USER is required}"
: "${SHSC_DB_APP_PASSWORD:?SHSC_DB_APP_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v db="$POSTGRES_DB" \
    -v migrator="$SHSC_DB_MIGRATOR_USER" -v migrator_pw="$SHSC_DB_MIGRATOR_PASSWORD" \
    -v app="$SHSC_DB_APP_USER" -v app_pw="$SHSC_DB_APP_PASSWORD" <<'EOSQL'
CREATE ROLE :"migrator" LOGIN PASSWORD :'migrator_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE :"app" LOGIN PASSWORD :'app_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
-- CREATE on the database lets the migrator install *trusted* extensions (citext, pg_trgm)
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE :"db" TO :"migrator";
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO :"app";

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA shsc AUTHORIZATION :"migrator";
GRANT USAGE ON SCHEMA shsc TO :"app";

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator" IN SCHEMA shsc
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator" IN SCHEMA shsc
    GRANT USAGE, SELECT ON SEQUENCES TO :"app";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator" IN SCHEMA shsc
    GRANT EXECUTE ON FUNCTIONS TO :"app";

ALTER ROLE :"migrator" SET search_path = shsc;
ALTER ROLE :"app" SET search_path = shsc;
EOSQL

echo "shsc: roles '$SHSC_DB_MIGRATOR_USER' and '$SHSC_DB_APP_USER' created"
