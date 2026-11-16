-- V001 baseline
-- Executed by the migrator role (owner of schema shsc). The runtime role only gets DML
-- privileges through ALTER DEFAULT PRIVILEGES configured at database initialisation.

-- Trusted extensions (creatable by a non-superuser that has CREATE on the database)
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA shsc;   -- case-insensitive e-mails
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA shsc;  -- CPE / product name search

-- Tenant context used by Row-Level Security policies (ADR-004).
-- The application sets it per transaction with: SELECT set_config('app.tenant_id', '<uuid>', true)
-- Returns NULL when not set, so RLS policies comparing tenant_id = current_tenant_id() match nothing.
CREATE FUNCTION shsc.current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

COMMENT ON FUNCTION shsc.current_tenant_id() IS
    'Tenant of the current transaction (app.tenant_id), NULL if not set. Used by RLS policies.';
