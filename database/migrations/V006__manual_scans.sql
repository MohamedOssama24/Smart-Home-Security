-- V006 manual scan workflow (Milestone 6)
--
-- * scans: one manual scan of a home, executed by one agent of that home. State machine of
--   docs/02-MANUAL-SCAN-WORKFLOW.md §2; the transitions are made by the application with
--   optimistic locking (version) and recorded in scan_events. At most one non-terminal scan
--   per home (partial unique index). Only MANUAL scans can exist (CHECK): no scheduler.
-- * scan_targets: snapshot of the authorized networks at creation time. Every address
--   reported by the agent must belong to one of them.
-- * scan_result_batches: idempotency of the uploads (scan_id, batch_seq).
-- * scan_observations: hosts observed by the agent (minimal discovery: interfaces + ARP).
--   They will be linked to the device inventory in the discovery/fingerprinting milestones.
-- * plans.max_scans_per_day: manual scans per home in 24 hours (FREE: 10).

CREATE TABLE scans (
    id                   uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id            uuid NOT NULL REFERENCES tenants (id),
    home_id              uuid NOT NULL,
    agent_id             uuid NOT NULL,
    trigger              text NOT NULL DEFAULT 'MANUAL' CHECK (trigger = 'MANUAL'),
    profile              text NOT NULL CHECK (profile IN ('DISCOVERY')),
    status               text NOT NULL CHECK (status IN ('PENDING', 'QUEUED', 'RUNNING', 'COMPLETED',
                                                         'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED')),
    requested_by         uuid NOT NULL REFERENCES users (id),
    requested_at         timestamptz NOT NULL,
    queued_at            timestamptz,
    job_expires_at       timestamptz,
    started_at           timestamptz,
    lease_expires_at     timestamptz,
    deadline_at          timestamptz,
    completed_at         timestamptz,
    cancel_requested_at  timestamptz,
    cancel_requested_by  uuid REFERENCES users (id),
    progress             jsonb CHECK (jsonb_typeof(progress) = 'object' AND pg_column_size(progress) <= 1024),
    devices_discovered   integer NOT NULL DEFAULT 0 CHECK (devices_discovered >= 0),
    out_of_scope_dropped integer NOT NULL DEFAULT 0 CHECK (out_of_scope_dropped >= 0),
    total_batches        integer CHECK (total_batches >= 0),
    warnings             jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(warnings) = 'array'
                                                            AND pg_column_size(warnings) <= 4096),
    failure_reason       text CHECK (failure_reason ~ '^[A-Z_]{1,40}$'),
    idempotency_key      text CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{8,64}$'),
    version              integer NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    UNIQUE (tenant_id, id),
    CHECK ((status = 'FAILED') = (failure_reason IS NOT NULL)),
    CHECK ((status IN ('COMPLETED', 'COMPLETED_WITH_WARNINGS', 'FAILED', 'CANCELLED')) = (completed_at IS NOT NULL))
);
-- at most one active scan per home (docs/02 §3.4)
CREATE UNIQUE INDEX scans_one_active_per_home ON scans (home_id) WHERE status IN ('PENDING', 'QUEUED', 'RUNNING');
-- double click / retried request with the same Idempotency-Key returns the same scan
CREATE UNIQUE INDEX scans_idempotency ON scans (requested_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX scans_home_idx ON scans (tenant_id, home_id, requested_at DESC);
CREATE INDEX scans_agent_queue_idx ON scans (agent_id, queued_at) WHERE status = 'QUEUED';

CREATE TABLE scan_targets (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    scan_id     uuid NOT NULL,
    type        text NOT NULL DEFAULT 'ALL_AUTHORIZED' CHECK (type IN ('ALL_AUTHORIZED')),
    network_id  uuid NOT NULL,
    cidr        cidr NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, network_id) REFERENCES networks (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, network_id)
);

CREATE TABLE scan_events (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    scan_id      uuid NOT NULL,
    from_status  text,
    to_status    text NOT NULL,
    actor_type   text NOT NULL CHECK (actor_type IN ('USER', 'AGENT', 'SYSTEM')),
    actor_id     uuid,
    reason       text CHECK (reason ~ '^[A-Z_]{1,40}$'),
    at           timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX scan_events_scan_idx ON scan_events (scan_id, at);

CREATE TABLE scan_result_batches (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    scan_id            uuid NOT NULL,
    batch_seq          integer NOT NULL CHECK (batch_seq BETWEEN 0 AND 9999),
    received_at        timestamptz NOT NULL,
    payload_sha256     text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    observation_count  integer NOT NULL CHECK (observation_count >= 0),
    dropped_count      integer NOT NULL CHECK (dropped_count >= 0),
    late               boolean NOT NULL DEFAULT false,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, batch_seq)
);

CREATE TABLE scan_observations (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    scan_id      uuid NOT NULL,
    ip           inet NOT NULL,
    mac          macaddr,
    method       text NOT NULL CHECK (method IN ('ARP', 'SELF')),
    interface    text CHECK (length(interface) <= 64),
    observed_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, ip, method)
);

ALTER TABLE plans ADD COLUMN max_scans_per_day integer CHECK (max_scans_per_day > 0);
UPDATE plans SET max_scans_per_day = 10 WHERE code = 'FREE';

-- ---------------------------------------------------------------------------
-- RBAC
-- ---------------------------------------------------------------------------
INSERT INTO permissions (code, description) VALUES
    ('scan:read',   'Read scans and their results'),
    ('scan:create', 'Start and cancel manual scans');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'scan:read'), ('SUPER_ADMIN', 'scan:create'),
    ('ORGANIZATION_ADMIN', 'scan:read'), ('ORGANIZATION_ADMIN', 'scan:create'),
    ('TECHNICIAN', 'scan:read'), ('TECHNICIAN', 'scan:create'),
    ('CUSTOMER', 'scan:read'), ('CUSTOMER', 'scan:create'),
    ('READ_ONLY', 'scan:read');

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scans
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE scan_targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_targets
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE scan_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_events
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE scan_result_batches ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_result_batches
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE scan_observations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_observations
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Reaper (allowed periodic job, never a scan): lists, across tenants, the scans whose job
-- was not collected in time, whose lease expired or whose maximum duration was exceeded.
-- Returns only identifiers; each scan is then failed in its own tenant-scoped transaction.
-- ---------------------------------------------------------------------------
CREATE FUNCTION scans_due_for_reaping(p_now timestamptz, p_limit integer)
    RETURNS TABLE (tenant_id uuid, scan_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT s.tenant_id, s.id FROM shsc.scans s
    WHERE (s.status = 'QUEUED' AND s.job_expires_at < p_now)
       OR (s.status = 'RUNNING' AND (s.lease_expires_at < p_now OR s.deadline_at < p_now))
    ORDER BY s.requested_at
    LIMIT p_limit
$$;

REVOKE EXECUTE ON FUNCTION scans_due_for_reaping(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scans_due_for_reaping(timestamptz, integer) TO ${appRole};
