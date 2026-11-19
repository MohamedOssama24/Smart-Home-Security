-- M11 - Risk engine (docs/20-RISK-ENGINE.md, docs/09-SECURITY-ANALYSIS-RISK.md §3).
--
-- * risk_snapshots: one row each time the security score of a home is computed, never
--   rewritten (a change of the weights gives a new engine_version, the old rows stay as they
--   were computed):
--   - trigger SCAN: at the completion of a scan, after the security analysis;
--   - trigger TRIAGE: a finding marked as false positive / accepted risk (or reopened) changes
--     the score; same scan and coverage as the last computed snapshot.
--   A DISCOVERY scan has no port data: the score is not computed (score NULL with
--   not_computed_reason), the coverage is still recorded.
--   breakdown: every deduction with its finding, factors and contribution, the per-device
--   totals and the findings excluded by triage ("Why this score?").
--   delta_from_previous: change from the previous computed snapshot of the home and its
--   reasons (new findings, findings no longer counted, new devices).

CREATE TABLE risk_snapshots (
    id                    uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id             uuid NOT NULL REFERENCES tenants (id),
    home_id               uuid NOT NULL,
    scan_id               uuid NOT NULL,
    trigger               text NOT NULL CHECK (trigger IN ('SCAN', 'TRIAGE')),
    score                 integer CHECK (score BETWEEN 0 AND 100),
    risk_level            text CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    rating                text CHECK (rating IN ('EXCELLENT', 'GOOD', 'FAIR', 'POOR', 'CRITICAL')),
    not_computed_reason   text CHECK (not_computed_reason ~ '^[A-Z_]{1,40}$'),
    coverage              numeric(4, 3) NOT NULL CHECK (coverage BETWEEN 0 AND 1),
    coverage_detail       jsonb NOT NULL CHECK (jsonb_typeof(coverage_detail) = 'object'
                                                AND octet_length(coverage_detail::text) <= 4096),
    provisional           boolean NOT NULL,
    breakdown             jsonb NOT NULL CHECK (jsonb_typeof(breakdown) = 'object'
                                                AND octet_length(breakdown::text) <= 262144),
    top_devices           jsonb NOT NULL CHECK (jsonb_typeof(top_devices) = 'array'
                                                AND octet_length(top_devices::text) <= 8192),
    delta_from_previous   jsonb CHECK (jsonb_typeof(delta_from_previous) = 'object'
                                       AND octet_length(delta_from_previous::text) <= 65536),
    computed_at           timestamptz NOT NULL,
    engine_version        text NOT NULL CHECK (engine_version ~ '^[0-9A-Za-z.-]{1,32}$'),
    FOREIGN KEY (tenant_id, home_id) REFERENCES homes (tenant_id, id),
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id),
    UNIQUE (tenant_id, id),
    CHECK ((score IS NULL) = (not_computed_reason IS NOT NULL)),
    CHECK ((score IS NULL) = (risk_level IS NULL) AND (score IS NULL) = (rating IS NULL))
);
CREATE INDEX risk_snapshots_home_idx ON risk_snapshots (tenant_id, home_id, computed_at DESC, id DESC);

ALTER TABLE risk_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_snapshots
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
