-- M8 - Device fingerprinting and classification (docs/17-DEVICE-FINGERPRINTING.md).
--
-- * oui_entries: IEEE MA-L / MA-M / MA-S registries (public reference data, not tenant data:
--   no RLS). Loaded by a platform administrator; the result is the maker of the network card,
--   a weak hint for the maker of the product.
-- * devices: device inventory of a home. Identity (home, MAC); without a MAC (hosts known
--   only through the router or IPv6) (home, address). Detected values come from the
--   fingerprinting of the last completed scan; the manual category always wins in the UI but
--   the detected one stays visible.
-- * device_identifications: the current value of every field with its confidence and sources.
-- * device_category_changes: history of the automatic and manual category changes.
-- * scan_observations.device_id: the device each observation was attributed to.

CREATE TABLE oui_entries (
    prefix         text PRIMARY KEY CHECK (prefix ~ '^[0-9A-F]{6}([0-9A-F]|[0-9A-F]{3})?$'),
    prefix_length  smallint NOT NULL CHECK (prefix_length IN (24, 28, 36)),
    organization   text NOT NULL CHECK (length(organization) BETWEEN 1 AND 255),
    registry       text NOT NULL CHECK (registry IN ('MA-L', 'MA-M', 'MA-S')),
    updated_at     timestamptz NOT NULL,
    CHECK (length(prefix) * 4 = prefix_length)
);
CREATE INDEX oui_entries_registry_idx ON oui_entries (registry);

CREATE TABLE devices (
    id                            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id                     uuid NOT NULL REFERENCES tenants (id),
    home_id                       uuid NOT NULL,
    mac                           macaddr,
    mac_randomized                boolean NOT NULL DEFAULT false,
    -- randomized MAC: another device of the home with the same name ("probably the same device")
    probable_same_as              uuid,
    current_ip                    inet NOT NULL,
    addresses                     inet[] NOT NULL DEFAULT '{}' CHECK (cardinality(addresses) <= 32),
    hostname                      text CHECK (length(hostname) BETWEEN 1 AND 255),
    manufacturer                  text CHECK (length(manufacturer) BETWEEN 1 AND 255),
    model                         text CHECK (length(model) BETWEEN 1 AND 255),
    os_name                       text CHECK (os_name IN ('WINDOWS', 'LINUX', 'MACOS', 'ANDROID', 'IOS', 'EMBEDDED_LINUX')),
    detected_category             text NOT NULL DEFAULT 'UNKNOWN_DEVICE',
    detected_category_confidence  text CHECK (detected_category_confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    manual_category               text,
    manual_category_by            uuid REFERENCES users (id),
    manual_category_at            timestamptz,
    overall_confidence            text NOT NULL CHECK (overall_confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    -- explanation of the automatic classification: score, matched rules, conflicts
    classification                jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(classification) = 'object'
                                                                     AND pg_column_size(classification) <= 8192),
    ruleset_version               text NOT NULL CHECK (length(ruleset_version) BETWEEN 1 AND 32),
    first_seen_at                 timestamptz NOT NULL,
    last_seen_at                  timestamptz NOT NULL,
    first_scan_id                 uuid NOT NULL,
    last_scan_id                  uuid NOT NULL,
    version                       integer NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, first_scan_id) REFERENCES scans (tenant_id, id),
    FOREIGN KEY (tenant_id, last_scan_id) REFERENCES scans (tenant_id, id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, probable_same_as) REFERENCES devices (tenant_id, id) ON DELETE SET NULL (probable_same_as),
    CHECK (detected_category IN ('ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP',
                                 'PRINTER', 'NAS', 'SMART_PLUG', 'SMART_SPEAKER', 'IOT', 'UNKNOWN_DEVICE')),
    CHECK (manual_category IN ('ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP',
                               'PRINTER', 'NAS', 'SMART_PLUG', 'SMART_SPEAKER', 'IOT', 'UNKNOWN_DEVICE')),
    CHECK ((manual_category IS NULL) = (manual_category_at IS NULL)),
    CHECK (NOT mac_randomized OR mac IS NOT NULL),
    CHECK (probable_same_as <> id)
);
-- identity of a device: (home, MAC) when the MAC is known
CREATE UNIQUE INDEX devices_home_mac ON devices (home_id, mac) WHERE mac IS NOT NULL;
-- without a MAC: one device per address
CREATE UNIQUE INDEX devices_home_ip_without_mac ON devices (home_id, current_ip) WHERE mac IS NULL;
CREATE INDEX devices_home_idx ON devices (tenant_id, home_id, last_seen_at DESC);

CREATE TABLE device_identifications (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid NOT NULL REFERENCES tenants (id),
    device_id        uuid NOT NULL,
    scan_id          uuid NOT NULL,
    field            text NOT NULL CHECK (field IN ('IP', 'MAC', 'MANUFACTURER', 'HOSTNAME', 'DEVICE_TYPE', 'MODEL',
                                                    'OS', 'FIRMWARE')),
    value            text NOT NULL CHECK (length(value) BETWEEN 1 AND 255),
    confidence       text NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    -- [{source, value, reliability}] and conflicting values
    sources          jsonb NOT NULL CHECK (jsonb_typeof(sources) = 'array' AND pg_column_size(sources) <= 4096),
    conflict         boolean NOT NULL DEFAULT false,
    ruleset_version  text NOT NULL,
    identified_at    timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (device_id, field)
);

CREATE TABLE device_category_changes (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    device_id     uuid NOT NULL,
    source        text NOT NULL CHECK (source IN ('AUTO', 'MANUAL')),
    old_category  text,
    new_category  text,
    scan_id       uuid,
    changed_by    uuid REFERENCES users (id),
    changed_at    timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (scan_id),
    CHECK ((source = 'MANUAL') = (changed_by IS NOT NULL))
);
CREATE INDEX device_category_changes_device_idx ON device_category_changes (device_id, changed_at DESC);

ALTER TABLE scan_observations ADD COLUMN device_id uuid;
ALTER TABLE scan_observations ADD FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id)
    ON DELETE SET NULL (device_id);
CREATE INDEX scan_observations_device_idx ON scan_observations (device_id) WHERE device_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- RBAC
-- ---------------------------------------------------------------------------
INSERT INTO permissions (code, description) VALUES
    ('device:read',     'Read the device inventory'),
    ('device:classify', 'Set or clear the manual category of a device');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'device:read'), ('SUPER_ADMIN', 'device:classify'),
    ('ORGANIZATION_ADMIN', 'device:read'), ('ORGANIZATION_ADMIN', 'device:classify'),
    ('TECHNICIAN', 'device:read'), ('TECHNICIAN', 'device:classify'),
    ('CUSTOMER', 'device:read'), ('CUSTOMER', 'device:classify'),
    ('READ_ONLY', 'device:read');

-- ---------------------------------------------------------------------------
-- Row-Level Security (oui_entries is public reference data: no tenant column)
-- ---------------------------------------------------------------------------
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON devices
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_identifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_identifications
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_category_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_category_changes
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
