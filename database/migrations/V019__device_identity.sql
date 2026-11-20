-- Milestone 20 (docs/29-ROADMAP-M19-M23.md, ADR-076): identification and device card.
-- * device_identifications: new fields PRODUCT_CODE and CPE; status VERIFIED / PROBABLE of the
--   value (UNKNOWN = no row); every source records its origin (ADR-076: two sources are
--   independent only with different origins).
-- * devices.custom_name: name given by the user, never written by a scan.
-- * device_identity_confirmations: value of a field confirmed by the user (VERIFIED, kept by
--   later scans; a different scanned value is shown as a conflict).
-- * device_identification_history: every change of value or status of a field (prerequisite
--   of the firmware change alerts of M22). Bounded by the application (last 50 per field).

ALTER TABLE device_identifications DROP CONSTRAINT device_identifications_field_check;
ALTER TABLE device_identifications ADD CONSTRAINT device_identifications_field_check
    CHECK (field IN ('IP', 'MAC', 'MANUFACTURER', 'HOSTNAME', 'DEVICE_TYPE', 'MODEL', 'OS', 'FIRMWARE',
                     'PRODUCT_CODE', 'CPE'));
ALTER TABLE device_identifications ADD COLUMN status text NOT NULL DEFAULT 'PROBABLE'
    CHECK (status IN ('VERIFIED', 'PROBABLE'));

ALTER TABLE devices ADD COLUMN custom_name text CHECK (length(custom_name) BETWEEN 1 AND 100);

CREATE TABLE device_identity_confirmations (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    device_id     uuid NOT NULL,
    field         text NOT NULL CHECK (field IN ('MANUFACTURER', 'MODEL', 'PRODUCT_CODE', 'FIRMWARE', 'CPE', 'OS')),
    value         text NOT NULL CHECK (length(value) BETWEEN 1 AND 255),
    confirmed_by  uuid NOT NULL REFERENCES users (id),
    confirmed_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (device_id, field)
);

CREATE TABLE device_identification_history (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    device_id   uuid NOT NULL,
    field       text NOT NULL CHECK (field IN ('IP', 'MAC', 'MANUFACTURER', 'HOSTNAME', 'DEVICE_TYPE', 'MODEL', 'OS',
                                               'FIRMWARE', 'PRODUCT_CODE', 'CPE')),
    old_value   text CHECK (length(old_value) BETWEEN 1 AND 255),
    new_value   text CHECK (length(new_value) BETWEEN 1 AND 255),
    old_status  text CHECK (old_status IN ('VERIFIED', 'PROBABLE')),
    new_status  text CHECK (new_status IN ('VERIFIED', 'PROBABLE')),
    origin      text NOT NULL CHECK (origin IN ('SCAN', 'USER')),
    scan_id     uuid,
    changed_by  uuid REFERENCES users (id),
    changed_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (scan_id),
    CHECK (old_value IS NOT NULL OR new_value IS NOT NULL)
);
CREATE INDEX device_identification_history_device_idx
    ON device_identification_history (device_id, field, changed_at DESC);

ALTER TABLE device_identity_confirmations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_identity_confirmations
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_identification_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_identification_history
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
