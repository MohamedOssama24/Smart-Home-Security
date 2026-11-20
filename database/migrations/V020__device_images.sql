-- M23: device images (ADR-077).
-- DEVICE: icon declared by the device itself (UPnP <iconList>), fetched by the agent only from the
-- device's own address on an authorized network; USER: photo uploaded by the user. Images are
-- stored locally, never linked to external sites. Formats PNG and JPEG only, checked by magic bytes.

-- icons received with the results of a scan, adopted by the device at fingerprinting time
CREATE TABLE scan_device_icons (
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    scan_id       uuid NOT NULL,
    ip            inet NOT NULL,
    origin        text NOT NULL CHECK (origin IN ('UPNP')),
    content_type  text NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg')),
    data          bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 32768),
    width         integer CHECK (width BETWEEN 1 AND 1024),
    height        integer CHECK (height BETWEEN 1 AND 1024),
    observed_at   timestamptz NOT NULL,
    PRIMARY KEY (scan_id, ip),
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE device_images (
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    device_id     uuid NOT NULL,
    source        text NOT NULL CHECK (source IN ('DEVICE', 'USER')),
    origin        text NOT NULL CHECK (origin IN ('UPNP', 'UPLOAD')),
    content_type  text NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg')),
    data          bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 1048576),
    sha256        text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    width         integer CHECK (width BETWEEN 1 AND 8192),
    height        integer CHECK (height BETWEEN 1 AND 8192),
    scan_id       uuid,
    uploaded_by   uuid REFERENCES users (id),
    updated_at    timestamptz NOT NULL,
    PRIMARY KEY (device_id, source),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE SET NULL (scan_id),
    CHECK ((source = 'USER') = (origin = 'UPLOAD')),
    CHECK (source = 'DEVICE' OR uploaded_by IS NOT NULL)
);

ALTER TABLE scan_device_icons ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_device_icons
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_images ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_images
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
