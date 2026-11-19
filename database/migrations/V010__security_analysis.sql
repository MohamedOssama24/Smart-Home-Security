-- M10 - Security analysis and vulnerability intelligence (docs/19-SECURITY-ANALYSIS.md,
-- docs/09-SECURITY-ANALYSIS-RISK.md §1-2).
--
-- Global reference data (public, no tenant column, no RLS), filled only when a platform
-- administrator starts a synchronization:
-- * vulnerabilities: CVE records of the NVD for the products of the curated CPE dictionary.
-- * vulnerability_cpe_matches: vulnerable CPE criteria of each CVE with their version range.
--   requires_platform: the CVE applies only together with another component (NVD "AND"
--   configuration): such a match is never "confirmed".
-- * vulnerability_kev: CISA Known Exploited Vulnerabilities catalog.
-- * vulnerability_epss: FIRST EPSS scores of the stored CVEs.
-- * vulnerability_feed_status: last synchronization of each feed.
--
-- Tenant data (RLS):
-- * findings: one per (device, fingerprint); lifecycle OPEN -> RESOLVED (a later scan that
--   covered the port/service no longer sees it) and manual triage ACKNOWLEDGED, FALSE_POSITIVE,
--   ACCEPTED_RISK (reason mandatory). Texts are i18n keys.
-- * finding_evidence: what each scan observed for a finding.
-- * device_vulnerabilities: CVEs matched to a device, with the match quality (PRODUCT_ONLY is
--   never confirmed).

CREATE TABLE vulnerabilities (
    cve_id          text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    published_at    timestamptz,
    modified_at     timestamptz,
    description     text CHECK (length(description) <= 4000),
    cvss_version    text CHECK (cvss_version IN ('4.0', '3.1', '3.0', '2.0')),
    cvss_score      numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_vector     text CHECK (length(cvss_vector) <= 200),
    severity        text CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    cwe             text[] NOT NULL DEFAULT '{}' CHECK (cardinality(cwe) <= 16),
    refs            jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refs) = 'array' AND octet_length(refs::text) <= 8192),
    status          text CHECK (length(status) <= 40),
    source          text NOT NULL DEFAULT 'NVD',
    synced_at       timestamptz NOT NULL
);

CREATE TABLE vulnerability_cpe_matches (
    id                    uuid PRIMARY KEY DEFAULT uuidv7(),
    cve_id                text NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    cpe23                 text NOT NULL CHECK (cpe23 LIKE 'cpe:2.3:%' AND length(cpe23) <= 512),
    part                  text NOT NULL CHECK (part IN ('a', 'o', 'h')),
    vendor                text NOT NULL CHECK (length(vendor) BETWEEN 1 AND 128),
    product               text NOT NULL CHECK (length(product) BETWEEN 1 AND 128),
    version               text CHECK (length(version) <= 64),
    version_update        text CHECK (length(version_update) <= 64),
    version_start_incl    text CHECK (length(version_start_incl) <= 64),
    version_start_excl    text CHECK (length(version_start_excl) <= 64),
    version_end_incl      text CHECK (length(version_end_incl) <= 64),
    version_end_excl      text CHECK (length(version_end_excl) <= 64),
    requires_platform     boolean NOT NULL DEFAULT false
);
CREATE INDEX vulnerability_cpe_matches_product_idx ON vulnerability_cpe_matches (vendor, product);
CREATE INDEX vulnerability_cpe_matches_cve_idx ON vulnerability_cpe_matches (cve_id);

CREATE TABLE vulnerability_kev (
    cve_id               text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor               text CHECK (length(vendor) <= 255),
    product              text CHECK (length(product) <= 255),
    name                 text CHECK (length(name) <= 512),
    date_added           date NOT NULL,
    due_date             date,
    known_ransomware     boolean NOT NULL DEFAULT false,
    synced_at            timestamptz NOT NULL
);

CREATE TABLE vulnerability_epss (
    cve_id       text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    score        numeric(6, 5) NOT NULL CHECK (score BETWEEN 0 AND 1),
    percentile   numeric(6, 5) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    score_date   date,
    synced_at    timestamptz NOT NULL
);

CREATE TABLE vulnerability_feed_status (
    feed              text PRIMARY KEY CHECK (feed IN ('NVD', 'KEV', 'EPSS')),
    state             text NOT NULL CHECK (state IN ('NEVER', 'RUNNING', 'OK', 'FAILED')),
    last_attempt_at   timestamptz,
    last_success_at   timestamptz,
    items             integer NOT NULL DEFAULT 0 CHECK (items >= 0),
    error_code        text CHECK (error_code ~ '^[A-Z_]{1,40}$')
);
INSERT INTO vulnerability_feed_status (feed, state) VALUES ('NVD', 'NEVER'), ('KEV', 'NEVER'), ('EPSS', 'NEVER');

CREATE TABLE findings (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id           uuid NOT NULL REFERENCES tenants (id),
    home_id             uuid NOT NULL,
    device_id           uuid NOT NULL,
    rule_id             text NOT NULL CHECK (rule_id ~ '^[a-z0-9.-]{1,64}$'),
    rule_version        integer NOT NULL CHECK (rule_version > 0),
    fingerprint         text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    title_key           text NOT NULL CHECK (length(title_key) <= 128),
    recommendation_key  text NOT NULL CHECK (length(recommendation_key) <= 128),
    params              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object'
                                                          AND octet_length(params::text) <= 2048),
    severity            text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    finding_type        text NOT NULL CHECK (finding_type IN ('CONFIRMED_VULNERABILITY', 'POTENTIAL_RISK',
                                                              'SUSPICIOUS_CONFIGURATION', 'UNVERIFIED_INFORMATION')),
    confidence          text NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW')),
    source              text NOT NULL CHECK (length(source) <= 64),
    protocol            text CHECK (protocol IN ('TCP', 'UDP')),
    port                integer CHECK (port BETWEEN 1 AND 65535),
    cve_id              text CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    status              text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED',
                                                                       'FALSE_POSITIVE', 'ACCEPTED_RISK')),
    status_reason       text CHECK (length(status_reason) BETWEEN 1 AND 500),
    status_changed_by   uuid REFERENCES users (id),
    status_changed_at   timestamptz,
    first_detected_at   timestamptz NOT NULL,
    last_detected_at    timestamptz NOT NULL,
    resolved_at         timestamptz,
    first_scan_id       uuid NOT NULL,
    last_scan_id        uuid NOT NULL,
    version             integer NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, first_scan_id) REFERENCES scans (tenant_id, id),
    FOREIGN KEY (tenant_id, last_scan_id) REFERENCES scans (tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (device_id, fingerprint),
    CHECK ((status = 'RESOLVED') = (resolved_at IS NOT NULL)),
    CHECK (status NOT IN ('FALSE_POSITIVE', 'ACCEPTED_RISK', 'ACKNOWLEDGED') OR status_reason IS NOT NULL)
);
CREATE INDEX findings_home_idx ON findings (tenant_id, home_id, status, severity);

CREATE TABLE finding_evidence (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    finding_id    uuid NOT NULL,
    scan_id       uuid NOT NULL,
    type          text NOT NULL CHECK (type ~ '^[A-Z_]{1,32}$'),
    data          jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object' AND octet_length(data::text) <= 4096),
    collected_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (finding_id, scan_id)
);

CREATE TABLE device_vulnerabilities (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    device_id      uuid NOT NULL,
    cve_id         text NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    finding_id     uuid NOT NULL,
    match_quality  text NOT NULL CHECK (match_quality IN ('EXACT_VERSION', 'VERSION_RANGE', 'PRODUCT_ONLY')),
    matched_cpe    text NOT NULL CHECK (length(matched_cpe) <= 512),
    product        text NOT NULL CHECK (length(product) <= 128),
    version        text CHECK (length(version) <= 64),
    scan_id        uuid NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (device_id, cve_id, finding_id)
);
CREATE INDEX device_vulnerabilities_finding_idx ON device_vulnerabilities (finding_id);

-- ---------------------------------------------------------------------------
-- RBAC
-- ---------------------------------------------------------------------------
INSERT INTO permissions (code, description) VALUES
    ('finding:read',   'Read the security findings and the matched vulnerabilities'),
    ('finding:triage', 'Acknowledge a finding or mark it as false positive / accepted risk');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'finding:read'), ('SUPER_ADMIN', 'finding:triage'),
    ('ORGANIZATION_ADMIN', 'finding:read'), ('ORGANIZATION_ADMIN', 'finding:triage'),
    ('TECHNICIAN', 'finding:read'), ('TECHNICIAN', 'finding:triage'),
    ('CUSTOMER', 'finding:read'), ('CUSTOMER', 'finding:triage'),
    ('READ_ONLY', 'finding:read');

-- ---------------------------------------------------------------------------
-- Row-Level Security (the vulnerability tables are public reference data)
-- ---------------------------------------------------------------------------
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON findings
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON finding_evidence
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE device_vulnerabilities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_vulnerabilities
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
