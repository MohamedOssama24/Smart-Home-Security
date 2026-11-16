-- V002 identity, tenancy, RBAC, user sessions, audit (Milestone 3)
--
-- Every tenant-scoped table has tenant_id + a Row-Level Security policy based on
-- shsc.current_tenant_id() (ADR-004). The runtime role is not the owner and has no
-- BYPASSRLS, so it only ever sees rows of the tenant set for the current transaction.
-- Pre-authentication lookups (login by e-mail, refresh token, e-mail tokens) go through
-- the narrow SECURITY DEFINER functions at the end of this file, which return only the
-- tenant id needed to open a properly scoped transaction.
--
-- Placeholder ${appRole} = runtime DB role (spring.flyway.placeholders.appRole).

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    type        text NOT NULL CHECK (type IN ('INDIVIDUAL', 'BUSINESS', 'PLATFORM')),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status      text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL UNIQUE REFERENCES tenants (id),
    legal_name  text NOT NULL CHECK (length(legal_name) BETWEEN 1 AND 200),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Users (identity). E-mail is globally unique; a user belongs to one tenant.
-- password_hash is nullable so that future external identities (OIDC) can exist
-- without a local password.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id           uuid NOT NULL REFERENCES tenants (id),
    email               citext NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    password_hash       text,
    display_name        text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    locale              text NOT NULL DEFAULT 'it' CHECK (locale IN ('it', 'en')),
    status              text NOT NULL DEFAULT 'PENDING_VERIFICATION'
                        CHECK (status IN ('PENDING_VERIFICATION', 'ACTIVE', 'DISABLED')),
    email_verified_at   timestamptz,
    password_changed_at timestamptz,
    last_login_at       timestamptz,
    mfa_enabled         boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_key UNIQUE (email)
);
CREATE INDEX users_tenant_idx ON users (tenant_id);

-- ---------------------------------------------------------------------------
-- RBAC catalogue (global reference data, read-only for the runtime role)
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    code         text PRIMARY KEY,
    description  text NOT NULL,
    assignable_scopes text[] NOT NULL
);

CREATE TABLE permissions (
    code         text PRIMARY KEY CHECK (code ~ '^[a-z]+:[a-z_]+$'),
    description  text NOT NULL
);

CREATE TABLE role_permissions (
    role_code        text NOT NULL REFERENCES roles (code),
    permission_code  text NOT NULL REFERENCES permissions (code),
    PRIMARY KEY (role_code, permission_code)
);

INSERT INTO roles (code, description, assignable_scopes) VALUES
    ('SUPER_ADMIN',        'Platform administration',                          ARRAY['PLATFORM']),
    ('ORGANIZATION_ADMIN', 'Full control of the tenant / organization',        ARRAY['TENANT', 'ORGANIZATION']),
    ('TECHNICIAN',         'Operates homes and agents, no user or billing management', ARRAY['TENANT', 'ORGANIZATION', 'HOME']),
    ('CUSTOMER',           'Owner of homes (B2C) or customer of an organization (B2B)', ARRAY['TENANT', 'HOME']),
    ('READ_ONLY',          'Read-only access to the assigned scope',           ARRAY['TENANT', 'ORGANIZATION', 'HOME']);

INSERT INTO permissions (code, description) VALUES
    ('platform:admin', 'Platform administration (cross-tenant, audited)'),
    ('tenant:read',    'Read tenant and organization information'),
    ('user:read',      'List users of the tenant'),
    ('user:manage',    'Manage users of the tenant'),
    ('role:manage',    'Assign and revoke roles'),
    ('home:read',      'Read homes'),
    ('home:write',     'Create and modify homes'),
    ('agent:read',     'Read agents and enrollment tokens'),
    ('agent:enroll',   'Create agent enrollment tokens'),
    ('agent:revoke',   'Revoke agents and enrollment tokens'),
    ('audit:read',     'Read the audit log of the tenant');

INSERT INTO role_permissions (role_code, permission_code)
SELECT 'SUPER_ADMIN', code FROM permissions;

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('ORGANIZATION_ADMIN', 'tenant:read'), ('ORGANIZATION_ADMIN', 'user:read'),
    ('ORGANIZATION_ADMIN', 'user:manage'), ('ORGANIZATION_ADMIN', 'role:manage'),
    ('ORGANIZATION_ADMIN', 'home:read'),   ('ORGANIZATION_ADMIN', 'home:write'),
    ('ORGANIZATION_ADMIN', 'agent:read'),  ('ORGANIZATION_ADMIN', 'agent:enroll'),
    ('ORGANIZATION_ADMIN', 'agent:revoke'), ('ORGANIZATION_ADMIN', 'audit:read'),

    ('TECHNICIAN', 'tenant:read'), ('TECHNICIAN', 'home:read'), ('TECHNICIAN', 'home:write'),
    ('TECHNICIAN', 'agent:read'),  ('TECHNICIAN', 'agent:enroll'), ('TECHNICIAN', 'agent:revoke'),

    ('CUSTOMER', 'tenant:read'), ('CUSTOMER', 'home:read'), ('CUSTOMER', 'home:write'),
    ('CUSTOMER', 'agent:read'),  ('CUSTOMER', 'agent:enroll'), ('CUSTOMER', 'agent:revoke'),
    ('CUSTOMER', 'audit:read'),

    ('READ_ONLY', 'tenant:read'), ('READ_ONLY', 'home:read'), ('READ_ONLY', 'agent:read');

-- ---------------------------------------------------------------------------
-- Homes (minimal in M3: needed for HOME-scoped permissions and agent binding;
-- extended in Milestone 4)
-- ---------------------------------------------------------------------------
CREATE TABLE homes (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    created_by  uuid REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    UNIQUE (tenant_id, id)
);
CREATE INDEX homes_tenant_idx ON homes (tenant_id, created_at);

-- ---------------------------------------------------------------------------
-- Role assignments with scope
-- ---------------------------------------------------------------------------
CREATE TABLE user_role_assignments (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_code   text NOT NULL REFERENCES roles (code),
    scope_type  text NOT NULL CHECK (scope_type IN ('PLATFORM', 'TENANT', 'ORGANIZATION', 'HOME')),
    scope_id    uuid,
    granted_by  uuid REFERENCES users (id),
    granted_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_type IN ('PLATFORM', 'TENANT')) = (scope_id IS NULL))
);
CREATE UNIQUE INDEX user_role_assignments_unique
    ON user_role_assignments (user_id, role_code, scope_type, coalesce(scope_id, '00000000-0000-0000-0000-000000000000'));
CREATE INDEX user_role_assignments_tenant_idx ON user_role_assignments (tenant_id, user_id);

-- ---------------------------------------------------------------------------
-- Sessions and refresh tokens (only SHA-256 hashes are stored)
-- ---------------------------------------------------------------------------
CREATE TABLE user_sessions (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_label    text CHECK (length(device_label) <= 100),
    user_agent      text CHECK (length(user_agent) <= 512),
    ip_address      text CHECK (length(ip_address) <= 64),
    auth_method     text NOT NULL DEFAULT 'PASSWORD' CHECK (auth_method IN ('PASSWORD')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_reason  text CHECK (revoked_reason IN ('LOGOUT', 'USER_REVOKED', 'REVOKE_ALL',
                        'PASSWORD_CHANGED', 'PASSWORD_RESET', 'TOKEN_REUSE', 'ADMIN'))
);
CREATE INDEX user_sessions_user_idx ON user_sessions (tenant_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    session_id   uuid NOT NULL REFERENCES user_sessions (id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);

-- One-time tokens sent by e-mail (verification, password reset)
CREATE TABLE user_action_tokens (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose     text NOT NULL CHECK (purpose IN ('EMAIL_VERIFICATION', 'PASSWORD_RESET')),
    token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);
CREATE INDEX user_action_tokens_user_idx ON user_action_tokens (user_id, purpose) WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- Brute-force throttling (not tenant data: keys are hashed e-mails and client IPs)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_throttle (
    key            text PRIMARY KEY CHECK (length(key) <= 200),
    failures       integer NOT NULL DEFAULT 0,
    window_start   timestamptz NOT NULL,
    blocked_until  timestamptz,
    lockouts       integer NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Audit log (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid REFERENCES tenants (id),
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    actor_type   text NOT NULL CHECK (actor_type IN ('USER', 'AGENT', 'SYSTEM', 'ANONYMOUS')),
    actor_id     uuid,
    action       text NOT NULL CHECK (action ~ '^[A-Z_]+$'),
    outcome      text NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE')),
    target_type  text,
    target_id    uuid,
    ip_address   text CHECK (length(ip_address) <= 64),
    user_agent   text CHECK (length(user_agent) <= 512),
    details      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, occurred_at DESC);

CREATE FUNCTION audit_logs_append_only() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();

-- Reference data and audit log cannot be altered by the runtime role
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON roles, permissions, role_permissions FROM ${appRole};
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM ${appRole};

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_tenant_id()) WITH CHECK (id = current_tenant_id());

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE homes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON homes
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE user_role_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_role_assignments
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_sessions
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE user_action_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_action_tokens
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- Audit: a tenant reads only its own events; events without tenant (e.g. failed login
-- for an unknown e-mail) can be written but are readable only by platform operators.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_logs FOR SELECT
    USING (tenant_id = current_tenant_id());
CREATE POLICY audit_insert ON audit_logs FOR INSERT
    WITH CHECK (tenant_id IS NULL OR tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Pre-authentication lookups (SECURITY DEFINER, owner = migrator, bypass RLS).
-- They return only the identifiers needed to open a tenant-scoped transaction.
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth_lookup_user(p_email citext)
    RETURNS TABLE (user_id uuid, tenant_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT u.id, u.tenant_id FROM shsc.users u WHERE u.email = p_email
$$;

-- p_kind: REFRESH_TOKEN | USER_ACTION_TOKEN (extended by V003 for agent secrets)
CREATE FUNCTION lookup_tenant_by_secret(p_kind text, p_hash bytea)
    RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
BEGIN
    IF p_kind = 'REFRESH_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.refresh_tokens WHERE token_hash = p_hash);
    ELSIF p_kind = 'USER_ACTION_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.user_action_tokens WHERE token_hash = p_hash);
    END IF;
    RAISE EXCEPTION 'unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
END
$$;

REVOKE EXECUTE ON FUNCTION auth_lookup_user(citext), lookup_tenant_by_secret(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_lookup_user(citext), lookup_tenant_by_secret(text, bytea) TO ${appRole};
