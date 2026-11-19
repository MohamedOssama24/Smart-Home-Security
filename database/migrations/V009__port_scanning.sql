-- M9 - Port and service detection (docs/18-PORT-SCANNING.md, docs/08-PORT-SCANNING-SERVICES.md).
--
-- * scans.profile: QUICK and STANDARD scan the ports of the discovered hosts (DEEP and CUSTOM
--   are plan-gated and come with the SaaS plans, M17).
-- * scan_observations.method PORTSCAN: per-host counters of the port scan (probed, open,
--   closed, filtered, open|filtered, unknown), the profile and the port list version.
-- * open_ports: only the OPEN ports of a host are stored, one row per scan (ADR-049): closed
--   and silent ports are counted in the PORTSCAN observation. Linked to the device by the
--   fingerprinting at the end of the scan.
-- * detected_services: the service identified on an open port, PROBABLE (port number or weak
--   evidence) or CONFIRMED (protocol answer), with the collected evidence and TLS data.
-- * detected_protocols: protocols spoken by a device in a scan (from the services and from the
--   discovery observations), used by the classification and later by the risk rules.
-- * scan_result_batches.port_count: open ports received in the batch.

ALTER TABLE scans DROP CONSTRAINT scans_profile_check;
ALTER TABLE scans ADD CONSTRAINT scans_profile_check CHECK (profile IN ('DISCOVERY', 'QUICK', 'STANDARD'));

ALTER TABLE scan_observations DROP CONSTRAINT scan_observations_method_check;
ALTER TABLE scan_observations ADD CONSTRAINT scan_observations_method_check
    CHECK (method IN ('ARP', 'SELF', 'ICMP', 'MDNS', 'SSDP', 'UPNP_IGD', 'NETBIOS', 'RDNS', 'NDP', 'TR064', 'SNMP',
                      'PORTSCAN'));

ALTER TABLE scan_result_batches ADD COLUMN port_count integer NOT NULL DEFAULT 0 CHECK (port_count >= 0);

CREATE TABLE open_ports (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    scan_id      uuid NOT NULL,
    device_id    uuid,
    ip           inet NOT NULL,
    protocol     text NOT NULL CHECK (protocol IN ('TCP', 'UDP')),
    port         integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state        text NOT NULL CHECK (state IN ('OPEN', 'CLOSED', 'FILTERED', 'OPEN_FILTERED', 'UNKNOWN')),
    reason       text CHECK (reason ~ '^[a-z-]{1,40}$'),
    observed_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE SET NULL (device_id),
    UNIQUE (tenant_id, id),
    UNIQUE (scan_id, ip, protocol, port)
);
CREATE INDEX open_ports_device_idx ON open_ports (device_id, scan_id) WHERE device_id IS NOT NULL;

CREATE TABLE detected_services (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    open_port_id  uuid NOT NULL UNIQUE,
    name          text NOT NULL CHECK (name ~ '^[a-z0-9-]{1,32}$'),
    product       text CHECK (length(product) BETWEEN 1 AND 128),
    version       text CHECK (length(version) BETWEEN 1 AND 64),
    status        text NOT NULL CHECK (status IN ('PROBABLE', 'CONFIRMED')),
    confidence    text NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    evidence      jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object'
                                                     AND octet_length(evidence::text) <= 4096),
    tls           jsonb CHECK (jsonb_typeof(tls) = 'object' AND octet_length(tls::text) <= 4096),
    FOREIGN KEY (tenant_id, open_port_id) REFERENCES open_ports (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE detected_protocols (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    device_id   uuid NOT NULL,
    scan_id     uuid NOT NULL,
    protocol    text NOT NULL CHECK (protocol ~ '^[A-Z0-9_]{1,32}$'),
    details     jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'
                                                   AND octet_length(details::text) <= 2048),
    confidence  text NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (scan_id, device_id, protocol)
);
CREATE INDEX detected_protocols_device_idx ON detected_protocols (device_id, scan_id);

-- ---------------------------------------------------------------------------
-- Row-Level Security (reading uses the existing device:read and scan:read permissions)
-- ---------------------------------------------------------------------------
ALTER TABLE open_ports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON open_ports
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE detected_services ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON detected_services
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE detected_protocols ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON detected_protocols
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
