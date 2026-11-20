-- Milestone 19 (docs/29-ROADMAP-M19-M23.md, ADR-074): complete inventory of a device.
--
-- * device_interfaces: every MAC address of a device (Ethernet + Wi-Fi, privacy MACs), unique in
--   the home. The identity of a device becomes "one of its interfaces"; devices.mac stays the
--   first MAC seen (compatibility with M8–M18).
-- * device_addresses: history of every IPv4/IPv6 address seen for the device, with first/last
--   sighting and the MAC it was seen with. Scope (private, link-local, ULA, global) and interface
--   identifier kind (EUI-64, random) are derived from the address by the backend, not stored.
--   IPv6 addresses with a random interface identifier (temporary / privacy) not seen for 30 days
--   are pruned by the backend at each scan; at most 256 addresses per device.
-- * devices.same_as_dismissed: devices the user said are NOT the same device (no new suggestion).

CREATE TABLE device_interfaces (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid NOT NULL REFERENCES tenants (id),
    home_id          uuid NOT NULL,
    device_id        uuid NOT NULL,
    mac              macaddr NOT NULL,
    mac_randomized   boolean NOT NULL,
    vendor           text CHECK (length(vendor) BETWEEN 1 AND 255),
    -- interface of the agent through which the MAC was last seen (e.g. "Ethernet", "wlan0")
    agent_interface  text CHECK (length(agent_interface) BETWEEN 1 AND 64),
    first_seen_at    timestamptz NOT NULL,
    last_seen_at     timestamptz NOT NULL,
    first_scan_id    uuid,
    last_scan_id     uuid,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, first_scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (first_scan_id),
    FOREIGN KEY (tenant_id, last_scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (last_scan_id),
    UNIQUE (home_id, mac),
    CHECK (last_seen_at >= first_seen_at)
);
CREATE INDEX device_interfaces_device_idx ON device_interfaces (device_id);

CREATE TABLE device_addresses (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid NOT NULL REFERENCES tenants (id),
    device_id        uuid NOT NULL,
    address          inet NOT NULL CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    mac              macaddr,
    first_seen_at    timestamptz NOT NULL,
    last_seen_at     timestamptz NOT NULL,
    first_scan_id    uuid,
    last_scan_id     uuid,
    times_seen       integer NOT NULL DEFAULT 1 CHECK (times_seen > 0),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, first_scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (first_scan_id),
    FOREIGN KEY (tenant_id, last_scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (last_scan_id),
    UNIQUE (device_id, address),
    CHECK (last_seen_at >= first_seen_at)
);
CREATE INDEX device_addresses_device_idx ON device_addresses (device_id, last_seen_at DESC);

ALTER TABLE devices ADD COLUMN same_as_dismissed uuid[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(same_as_dismissed) <= 64);

-- Backfill from the M8 inventory: the known MAC and the current addresses.
INSERT INTO device_interfaces (tenant_id, home_id, device_id, mac, mac_randomized, first_seen_at, last_seen_at,
                               first_scan_id, last_scan_id)
SELECT tenant_id, home_id, id, mac, mac_randomized, first_seen_at, last_seen_at, first_scan_id, last_scan_id
FROM devices WHERE mac IS NOT NULL;

INSERT INTO device_addresses (tenant_id, device_id, address, mac, first_seen_at, last_seen_at, first_scan_id,
                              last_scan_id)
SELECT d.tenant_id, d.id, a.address, d.mac, d.first_seen_at, d.last_seen_at, d.first_scan_id, d.last_scan_id
FROM devices d CROSS JOIN LATERAL (SELECT DISTINCT unnest(d.addresses || d.current_ip) AS address) a;

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE device_interfaces ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_interfaces
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_addresses ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_addresses
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
