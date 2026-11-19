-- Milestone 15: Home Assistant integration (docs/24-INTEGRATIONS.md).
-- The URL and the long-lived token of Home Assistant stay on the agent (AGENT_LOCAL): the backend
-- only receives, with the scan results, the read-only inventory of the devices known to Home
-- Assistant (including Zigbee, Z-Wave, Matter, Thread and Bluetooth devices, which have no IP).

-- one Home Assistant instance per scan
CREATE TABLE scan_home_assistant (
    scan_id       uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    ip            inet NOT NULL,
    version       text CHECK (version ~ '^[0-9A-Za-z.+-]{1,40}$'),
    https         boolean NOT NULL,
    device_count  integer NOT NULL CHECK (device_count BETWEEN 0 AND 2000),
    truncated     boolean NOT NULL DEFAULT false,
    observed_at   timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE scan_gateway_devices (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    scan_id       uuid NOT NULL,
    source        text NOT NULL CHECK (source IN ('HOME_ASSISTANT')),
    position      integer NOT NULL CHECK (position BETWEEN 0 AND 1999),
    name          text CHECK (length(name) BETWEEN 1 AND 255),
    manufacturer  text CHECK (length(manufacturer) BETWEEN 1 AND 128),
    model         text CHECK (length(model) BETWEEN 1 AND 128),
    sw_version    text CHECK (length(sw_version) BETWEEN 1 AND 64),
    protocol      text NOT NULL CHECK (protocol IN ('ZIGBEE', 'ZWAVE', 'MATTER', 'THREAD', 'BLUETOOTH', 'IP', 'OTHER')),
    macs          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(macs) <= 8),
    entity_count  integer NOT NULL CHECK (entity_count BETWEEN 0 AND 10000),
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, source, position)
);

ALTER TABLE scan_home_assistant ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_home_assistant
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE scan_gateway_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_gateway_devices
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
