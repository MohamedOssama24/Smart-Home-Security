-- V003 local agent authentication (Milestone 3)
-- Agents have their own identity, completely separate from user JWTs:
--   enrollment token (one-time, expiring, hashed) -> agent + Ed25519 public key
--   signed assertion (private_key_jwt style)      -> short-lived opaque access token (hashed)

CREATE TABLE agent_enrollment_tokens (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    home_id            uuid NOT NULL,
    token_hash         bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_by         uuid NOT NULL REFERENCES users (id),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    used_at            timestamptz,
    used_by_agent_id   uuid,
    revoked_at         timestamptz,
    revoked_by         uuid REFERENCES users (id),
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id)
);
CREATE INDEX agent_enrollment_tokens_home_idx ON agent_enrollment_tokens (tenant_id, home_id, created_at DESC);

CREATE TABLE agents (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    home_id        uuid NOT NULL,
    name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    hostname       text CHECK (length(hostname) <= 255),
    os             text NOT NULL CHECK (os IN ('windows', 'linux', 'darwin')),
    arch           text NOT NULL CHECK (arch ~ '^[a-z0-9_]{1,16}$'),
    agent_version  text NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
    status         text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    enrolled_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz,
    revoked_at     timestamptz,
    revoked_by     uuid REFERENCES users (id),
    revoke_reason  text CHECK (length(revoke_reason) <= 200),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX agents_home_idx ON agents (tenant_id, home_id);

ALTER TABLE agent_enrollment_tokens
    ADD FOREIGN KEY (tenant_id, used_by_agent_id) REFERENCES agents (tenant_id, id);

CREATE TABLE agent_credentials (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    agent_id       uuid NOT NULL,
    algorithm      text NOT NULL DEFAULT 'Ed25519' CHECK (algorithm = 'Ed25519'),
    public_key     bytea NOT NULL CHECK (length(public_key) = 32),
    status         text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'ROTATED', 'REVOKED')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    retired_at     timestamptz,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    UNIQUE (tenant_id, id)
);
-- at most one active key per agent
CREATE UNIQUE INDEX agent_credentials_one_active ON agent_credentials (agent_id) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX agent_credentials_public_key ON agent_credentials (public_key);

-- Anti-replay of signed assertions (jti seen until the assertion expires)
CREATE TABLE agent_assertion_jti (
    agent_id    uuid NOT NULL,
    jti         text NOT NULL CHECK (length(jti) BETWEEN 16 AND 128),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (agent_id, jti),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id)
);

CREATE TABLE agent_access_tokens (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    agent_id       uuid NOT NULL,
    credential_id  uuid NOT NULL,
    token_hash     bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    FOREIGN KEY (tenant_id, credential_id) REFERENCES agent_credentials (tenant_id, id)
);
CREATE INDEX agent_access_tokens_agent_idx ON agent_access_tokens (agent_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE agent_enrollment_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_enrollment_tokens
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_credentials
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE agent_assertion_jti ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_assertion_jti
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE agent_access_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_access_tokens
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Pre-authentication lookups for agents
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION lookup_tenant_by_secret(p_kind text, p_hash bytea)
    RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
BEGIN
    IF p_kind = 'REFRESH_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.refresh_tokens WHERE token_hash = p_hash);
    ELSIF p_kind = 'USER_ACTION_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.user_action_tokens WHERE token_hash = p_hash);
    ELSIF p_kind = 'AGENT_ENROLLMENT_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.agent_enrollment_tokens WHERE token_hash = p_hash);
    ELSIF p_kind = 'AGENT_ACCESS_TOKEN' THEN
        RETURN (SELECT tenant_id FROM shsc.agent_access_tokens WHERE token_hash = p_hash);
    END IF;
    RAISE EXCEPTION 'unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
END
$$;

CREATE FUNCTION agent_lookup_tenant(p_agent_id uuid)
    RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT tenant_id FROM shsc.agents WHERE id = p_agent_id
$$;

-- Maintenance: removes expired authentication material across tenants.
-- Returns the number of deleted rows. Called by a periodic maintenance job (not a scan).
CREATE FUNCTION purge_expired_auth_data(p_retention interval)
    RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
DECLARE
    total bigint := 0;
    n bigint;
BEGIN
    DELETE FROM shsc.agent_assertion_jti WHERE expires_at < now();
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    DELETE FROM shsc.agent_access_tokens WHERE expires_at < now() - p_retention;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    DELETE FROM shsc.refresh_tokens WHERE expires_at < now() - p_retention;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    DELETE FROM shsc.user_action_tokens WHERE expires_at < now() - p_retention;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    DELETE FROM shsc.auth_throttle
        WHERE updated_at < now() - p_retention AND (blocked_until IS NULL OR blocked_until < now());
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    RETURN total;
END
$$;

REVOKE EXECUTE ON FUNCTION agent_lookup_tenant(uuid), purge_expired_auth_data(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_lookup_tenant(uuid), purge_expired_auth_data(interval) TO ${appRole};
