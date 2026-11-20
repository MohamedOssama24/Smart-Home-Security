-- Milestone 24 (docs/30-DEVICE-PEOPLE.md, ADR-081): device <-> person association.
-- * home_people: the people of a home (only a label; optional link to an existing account).
--   origin: who created the person (USER, or an automatic source). dismissed: an automatic
--   person deleted by the user, kept only as a name so that later scans do not create it again
--   (no association is kept).
-- * device_person_assignments: PROBABLE (automatic, shown with source and evidence), CONFIRMED
--   (by a user) or REJECTED (removed by a user: never proposed again by the same scans).
-- Minimization: no location, no presence history, no traffic data.

CREATE TABLE home_people (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    home_id       uuid NOT NULL,
    display_name  text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    user_id       uuid REFERENCES users (id) ON DELETE SET NULL,
    origin        text NOT NULL CHECK (origin IN ('USER', 'DEVICE_NAME', 'HOME_ASSISTANT', 'DIRECTORY', 'FIREWALL')),
    external_key  text CHECK (length(external_key) BETWEEN 1 AND 255),
    dismissed     boolean NOT NULL DEFAULT false,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX home_people_name_idx ON home_people (home_id, lower(display_name));
CREATE UNIQUE INDEX home_people_external_idx ON home_people (home_id, origin, external_key)
    WHERE external_key IS NOT NULL;

CREATE TABLE device_person_assignments (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    device_id   uuid NOT NULL,
    person_id   uuid NOT NULL,
    status      text NOT NULL CHECK (status IN ('PROBABLE', 'CONFIRMED', 'REJECTED')),
    source      text NOT NULL CHECK (source IN ('USER', 'DEVICE_NAME', 'HOME_ASSISTANT', 'DIRECTORY', 'FIREWALL')),
    evidence    text CHECK (length(evidence) BETWEEN 1 AND 255),
    decided_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, person_id) REFERENCES home_people (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (device_id, person_id)
);
CREATE INDEX device_person_assignments_person_idx ON device_person_assignments (person_id);

ALTER TABLE home_people ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON home_people
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_person_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_person_assignments
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

INSERT INTO permissions (code, description) VALUES
    ('person:read',   'See the people of a home and the devices assigned to them'),
    ('person:manage', 'Create, rename and delete people; assign devices to them');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'person:read'), ('SUPER_ADMIN', 'person:manage'),
    ('ORGANIZATION_ADMIN', 'person:read'), ('ORGANIZATION_ADMIN', 'person:manage'),
    ('TECHNICIAN', 'person:read'), ('TECHNICIAN', 'person:manage'),
    ('CUSTOMER', 'person:read'), ('CUSTOMER', 'person:manage');
