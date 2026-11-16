-- V004 users, organizations, customers, homes, networks and FREE plan limits (Milestone 4)
--
-- * plans: global reference data (read-only for the runtime role). Only FREE exists until
--   the SaaS milestone; a NULL limit means "unlimited".
-- * customers: end customers managed by a BUSINESS tenant (B2B). Homes may belong to one.
-- * CUSTOMER scope: a role can be granted on a single customer (all its homes).
-- * networks: networks of a home declared by the user (source MANUAL). Only private ranges of
--   bounded size are accepted, here and in the application. A network can be scanned only
--   after an explicit authorization (attestation), kept with full history.
-- * INVITATION: one-time e-mail token with which an invited user sets the password.

-- ---------------------------------------------------------------------------
-- Plans
-- ---------------------------------------------------------------------------
CREATE TABLE plans (
    code                   text PRIMARY KEY CHECK (code ~ '^[A-Z_]{2,30}$'),
    description            text NOT NULL,
    max_homes              integer CHECK (max_homes > 0),
    max_users              integer CHECK (max_users > 0),
    max_customers          integer CHECK (max_customers >= 0),
    max_networks_per_home  integer CHECK (max_networks_per_home > 0)
);

INSERT INTO plans (code, description, max_homes, max_users, max_customers, max_networks_per_home) VALUES
    ('FREE', 'Free plan', 2, 3, 2, 4);

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON plans FROM ${appRole};

ALTER TABLE tenants ADD COLUMN plan_code text NOT NULL DEFAULT 'FREE' REFERENCES plans (code);

-- ---------------------------------------------------------------------------
-- Organization details (BUSINESS tenants)
-- ---------------------------------------------------------------------------
ALTER TABLE organizations
    ADD COLUMN vat_number    text CHECK (vat_number ~ '^[A-Z0-9]{2,20}$'),
    ADD COLUMN contact_email citext CHECK (length(contact_email) BETWEEN 3 AND 254),
    ADD COLUMN contact_phone text CHECK (contact_phone ~ '^[+0-9 ()./-]{4,30}$');

-- ---------------------------------------------------------------------------
-- Customers of an organization
-- ---------------------------------------------------------------------------
CREATE TABLE customers (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    display_name   text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    contact_email  citext CHECK (length(contact_email) BETWEEN 3 AND 254),
    contact_phone  text CHECK (contact_phone ~ '^[+0-9 ()./-]{4,30}$'),
    notes          text CHECK (length(notes) <= 1000),
    created_by     uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    archived_at    timestamptz,
    UNIQUE (tenant_id, id)
);
CREATE INDEX customers_tenant_idx ON customers (tenant_id, display_name) WHERE archived_at IS NULL;

-- ---------------------------------------------------------------------------
-- Homes: customer, address, time zone
-- ---------------------------------------------------------------------------
ALTER TABLE homes
    ADD COLUMN customer_id uuid,
    ADD COLUMN address     text CHECK (length(address) <= 300),
    ADD COLUMN timezone    text NOT NULL DEFAULT 'Europe/Rome' CHECK (timezone ~ '^[A-Za-z0-9_+/-]{1,64}$'),
    ADD FOREIGN KEY (tenant_id, customer_id) REFERENCES customers (tenant_id, id);
CREATE INDEX homes_customer_idx ON homes (tenant_id, customer_id) WHERE archived_at IS NULL;

-- ---------------------------------------------------------------------------
-- Networks of a home and their authorization for scanning
-- ---------------------------------------------------------------------------
CREATE TABLE networks (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    home_id     uuid NOT NULL,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    cidr        cidr NOT NULL,
    kind        text NOT NULL DEFAULT 'UNKNOWN' CHECK (kind IN ('ETHERNET', 'WIFI', 'VLAN', 'GUEST', 'UNKNOWN')),
    source      text NOT NULL DEFAULT 'MANUAL' CHECK (source IN ('MANUAL')),
    created_by  uuid REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (home_id, cidr),
    -- only private / link-local ranges: public addresses and CGNAT (100.64.0.0/10) are never accepted
    CONSTRAINT networks_private_range CHECK (
        cidr <<= '10.0.0.0/8' OR cidr <<= '172.16.0.0/12' OR cidr <<= '192.168.0.0/16'
        OR cidr <<= '169.254.0.0/16' OR cidr <<= 'fc00::/7' OR cidr <<= 'fe80::/10'),
    -- size limit: at most 1024 IPv4 addresses (/22); IPv6 at most a /64
    CONSTRAINT networks_size_limit CHECK (
        (family(cidr) = 4 AND masklen(cidr) BETWEEN 22 AND 32)
        OR (family(cidr) = 6 AND masklen(cidr) BETWEEN 64 AND 128))
);
CREATE INDEX networks_home_idx ON networks (tenant_id, home_id);

CREATE TABLE network_authorizations (
    id                   uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id            uuid NOT NULL REFERENCES tenants (id),
    network_id           uuid NOT NULL,
    authorized_by        uuid NOT NULL REFERENCES users (id),
    authorized_at        timestamptz NOT NULL DEFAULT now(),
    attestation_version  text NOT NULL CHECK (attestation_version ~ '^[0-9]{1,4}$'),
    revoked_at           timestamptz,
    revoked_by           uuid REFERENCES users (id),
    FOREIGN KEY (tenant_id, network_id) REFERENCES networks (tenant_id, id) ON DELETE CASCADE,
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
-- at most one active authorization per network
CREATE UNIQUE INDEX network_authorizations_active ON network_authorizations (network_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- RBAC: CUSTOMER scope and new permissions
-- ---------------------------------------------------------------------------
ALTER TABLE user_role_assignments DROP CONSTRAINT user_role_assignments_scope_type_check;
ALTER TABLE user_role_assignments ADD CONSTRAINT user_role_assignments_scope_type_check
    CHECK (scope_type IN ('PLATFORM', 'TENANT', 'ORGANIZATION', 'CUSTOMER', 'HOME'));

UPDATE roles SET assignable_scopes = ARRAY['TENANT', 'ORGANIZATION', 'CUSTOMER', 'HOME']
    WHERE code IN ('TECHNICIAN', 'READ_ONLY');
UPDATE roles SET assignable_scopes = ARRAY['TENANT', 'CUSTOMER', 'HOME'] WHERE code = 'CUSTOMER';

INSERT INTO permissions (code, description) VALUES
    ('organization:manage', 'Modify the organization details'),
    ('customer:read',       'Read customers'),
    ('customer:manage',     'Create, modify and archive customers'),
    ('network:manage',      'Declare, modify and remove networks of a home'),
    ('network:authorize',   'Authorize networks for scanning (attestation)');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'organization:manage'), ('SUPER_ADMIN', 'customer:read'), ('SUPER_ADMIN', 'customer:manage'),
    ('SUPER_ADMIN', 'network:manage'), ('SUPER_ADMIN', 'network:authorize'),

    ('ORGANIZATION_ADMIN', 'organization:manage'), ('ORGANIZATION_ADMIN', 'customer:read'),
    ('ORGANIZATION_ADMIN', 'customer:manage'), ('ORGANIZATION_ADMIN', 'network:manage'),
    ('ORGANIZATION_ADMIN', 'network:authorize'),

    ('TECHNICIAN', 'customer:read'), ('TECHNICIAN', 'network:manage'), ('TECHNICIAN', 'network:authorize'),

    ('CUSTOMER', 'customer:read'), ('CUSTOMER', 'network:manage'), ('CUSTOMER', 'network:authorize'),

    ('READ_ONLY', 'customer:read');

-- ---------------------------------------------------------------------------
-- Invitations (one-time e-mail token to set the first password)
-- ---------------------------------------------------------------------------
ALTER TABLE user_action_tokens DROP CONSTRAINT user_action_tokens_purpose_check;
ALTER TABLE user_action_tokens ADD CONSTRAINT user_action_tokens_purpose_check
    CHECK (purpose IN ('EMAIL_VERIFICATION', 'PASSWORD_RESET', 'INVITATION'));

-- ---------------------------------------------------------------------------
-- Row-Level Security
-- ---------------------------------------------------------------------------
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON customers
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE networks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON networks
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE network_authorizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON network_authorizations
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
