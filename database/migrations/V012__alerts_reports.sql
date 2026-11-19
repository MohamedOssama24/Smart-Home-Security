-- M13 - Alerts and PDF reports (docs/22-ALERTS-REPORTS.md, docs/04-DATABASE.md "Notifiche, report").
--
-- * alerts: one row per event of a home. dedup_key identifies the same event: while an alert with
--   the same key is unresolved, a new occurrence only increments occurrences / last_at (no new
--   e-mail). State alerts (agent offline) are resolved when the condition ends.
-- * alert_deliveries: one row per recipient and channel, decided at creation from the user's
--   permissions on the home and preferences. DASHBOARD rows are the user's inbox (read_at per
--   user); EMAIL rows are sent by a periodic dispatcher (PENDING -> SENT / FAILED, max 3 attempts).
-- * notification_preferences: overrides of the defaults per user, alert type and channel.
-- * reports: PDF report of a scan (IT/EN), generated asynchronously and stored in the database
--   (bytea, small documents; no object storage in the MVP - ADR-067).

CREATE TABLE alerts (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    home_id      uuid NOT NULL,
    device_id    uuid,
    type         text NOT NULL CHECK (type IN ('NEW_FINDING', 'FINDING_RESOLVED', 'SCORE_DROPPED', 'NEW_DEVICE',
                                               'SCAN_FAILED', 'AGENT_OFFLINE')),
    severity     text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    dedup_key    text NOT NULL CHECK (dedup_key ~ '^[A-Za-z0-9:._-]{1,200}$'),
    occurrences  integer NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    first_at     timestamptz NOT NULL,
    last_at      timestamptz NOT NULL,
    resolved_at  timestamptz,
    payload      jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 8192),
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE SET NULL (device_id),
    UNIQUE (tenant_id, id)
);
-- deduplication: at most one unresolved alert per key
CREATE UNIQUE INDEX alerts_dedup_idx ON alerts (tenant_id, dedup_key) WHERE resolved_at IS NULL;
CREATE INDEX alerts_home_idx ON alerts (tenant_id, home_id, last_at DESC);

CREATE TABLE alert_deliveries (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    alert_id     uuid NOT NULL,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    channel      text NOT NULL CHECK (channel IN ('DASHBOARD', 'EMAIL')),
    status       text NOT NULL CHECK (status IN ('DELIVERED', 'PENDING', 'SENT', 'FAILED')),
    read_at      timestamptz,
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    next_attempt_at timestamptz,
    sent_at      timestamptz,
    error        text CHECK (error ~ '^[A-Z_]{1,40}$'),
    created_at   timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (alert_id, user_id, channel),
    CHECK ((channel = 'DASHBOARD') = (status = 'DELIVERED')),
    CHECK (channel = 'DASHBOARD' OR read_at IS NULL)
);
CREATE INDEX alert_deliveries_inbox_idx ON alert_deliveries (tenant_id, user_id, channel, created_at DESC);
CREATE INDEX alert_deliveries_due_idx ON alert_deliveries (next_attempt_at) WHERE status = 'PENDING';

CREATE TABLE notification_preferences (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    alert_type    text NOT NULL CHECK (alert_type IN ('NEW_FINDING', 'FINDING_RESOLVED', 'SCORE_DROPPED',
                                                      'NEW_DEVICE', 'SCAN_FAILED', 'AGENT_OFFLINE')),
    channel       text NOT NULL CHECK (channel IN ('DASHBOARD', 'EMAIL')),
    enabled       boolean NOT NULL,
    min_severity  text NOT NULL CHECK (min_severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    updated_at    timestamptz NOT NULL,
    UNIQUE (user_id, alert_type, channel)
);

CREATE TABLE reports (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    home_id       uuid NOT NULL,
    scan_id       uuid NOT NULL,
    locale        text NOT NULL CHECK (locale IN ('it', 'en')),
    status        text NOT NULL CHECK (status IN ('PENDING', 'READY', 'FAILED')),
    error_code    text CHECK (error_code ~ '^[A-Z_]{1,40}$'),
    content       bytea CHECK (octet_length(content) <= 10485760),
    size_bytes    integer,
    sha256        text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    pages         integer,
    generated_by  uuid REFERENCES users (id),
    requested_at  timestamptz NOT NULL,
    generated_at  timestamptz,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id),
    CHECK ((status = 'READY') = (content IS NOT NULL AND sha256 IS NOT NULL AND generated_at IS NOT NULL)),
    CHECK ((status = 'FAILED') = (error_code IS NOT NULL))
);
CREATE INDEX reports_home_idx ON reports (tenant_id, home_id, requested_at DESC);

-- ---------------------------------------------------------------------------
-- RBAC
-- ---------------------------------------------------------------------------
INSERT INTO permissions (code, description) VALUES
    ('report:generate', 'Generate the PDF security report of a scan');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'report:generate'), ('ORGANIZATION_ADMIN', 'report:generate'),
    ('TECHNICIAN', 'report:generate'), ('CUSTOMER', 'report:generate');

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON alerts
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE alert_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON alert_deliveries
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_preferences
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reports
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Periodic jobs across tenants: SECURITY DEFINER functions returning only identifiers; each item
-- is then processed in its own tenant-scoped transaction (same pattern as scans_due_for_reaping).
-- ---------------------------------------------------------------------------
CREATE FUNCTION alert_emails_due(p_now timestamptz, p_limit integer)
    RETURNS TABLE (tenant_id uuid, delivery_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT d.tenant_id, d.id FROM shsc.alert_deliveries d
    WHERE d.status = 'PENDING' AND d.next_attempt_at <= p_now
    ORDER BY d.next_attempt_at
    LIMIT p_limit
$$;
REVOKE EXECUTE ON FUNCTION alert_emails_due(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION alert_emails_due(timestamptz, integer) TO ${appRole};

-- active agents whose last heartbeat is older than the cutoff (OFFLINE, docs/03-AGENT-PROTOCOL.md §5)
CREATE FUNCTION agents_offline_since(p_cutoff timestamptz, p_limit integer)
    RETURNS TABLE (tenant_id uuid, agent_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT a.tenant_id, a.id FROM shsc.agents a
    WHERE a.status = 'ACTIVE' AND a.last_heartbeat_at < p_cutoff
      AND NOT EXISTS (SELECT 1 FROM shsc.alerts al
                      WHERE al.tenant_id = a.tenant_id AND al.resolved_at IS NULL
                        AND al.dedup_key = 'agent-offline:' || a.id::text)
    ORDER BY a.last_heartbeat_at
    LIMIT p_limit
$$;
REVOKE EXECUTE ON FUNCTION agents_offline_since(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agents_offline_since(timestamptz, integer) TO ${appRole};
