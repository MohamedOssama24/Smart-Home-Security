-- V005 agent runtime (Milestone 5)
--
-- * heartbeat: the agent reports liveness and its self-diagnosis (capabilities, network
--   interfaces, local queue depth, last error) every 25 s. The connectivity state shown to
--   users (ONLINE / STALE / OFFLINE) is computed from last_heartbeat_at when read.
-- * agent_events: events the agent queued locally (SQLite) and delivered when the backend was
--   reachable; idempotent thanks to the agent-chosen event_id. At most 500 per agent are kept.
-- * plans.max_agents_per_home: limit of active agents per home (FREE: 2).

ALTER TABLE agents
    ADD COLUMN last_heartbeat_at timestamptz,
    ADD COLUMN capabilities      jsonb CHECK (jsonb_typeof(capabilities) = 'object'
                                              AND pg_column_size(capabilities) <= 4096),
    ADD COLUMN interfaces        jsonb CHECK (jsonb_typeof(interfaces) = 'array'
                                              AND pg_column_size(interfaces) <= 65536),
    ADD COLUMN interfaces_hash   text CHECK (interfaces_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN queue_depth       integer CHECK (queue_depth >= 0),
    ADD COLUMN uptime_seconds    bigint CHECK (uptime_seconds >= 0),
    ADD COLUMN last_error        text CHECK (length(last_error) <= 300);

CREATE TABLE agent_events (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    agent_id     uuid NOT NULL,
    event_id     uuid NOT NULL,
    type         text NOT NULL CHECK (type IN ('AGENT_STARTED', 'AGENT_STOPPED', 'CAPABILITIES_CHANGED',
                                               'CONNECTION_RESTORED', 'QUEUE_OVERFLOW')),
    occurred_at  timestamptz NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    detail       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'
                                                    AND pg_column_size(detail) <= 4096),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    UNIQUE (agent_id, event_id)
);
CREATE INDEX agent_events_agent_idx ON agent_events (tenant_id, agent_id, occurred_at DESC);

ALTER TABLE agent_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_events
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE plans ADD COLUMN max_agents_per_home integer CHECK (max_agents_per_home > 0);
UPDATE plans SET max_agents_per_home = 2 WHERE code = 'FREE';
