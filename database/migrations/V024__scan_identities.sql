-- M24 part 2/3 (ADR-083): who used which address of the home, as reported by the agent from the
-- owner's Active Directory logons (DIRECTORY) and Sophos firewall authentications (FIREWALL).
-- Only the pair address ↔ account of the authorized networks of the scan is stored; the rows go
-- with their scan (deleting a scan or clearing the inventory deletes them).
CREATE TABLE scan_identities (
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    scan_id      uuid NOT NULL,
    address      inet NOT NULL CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    account      varchar(100) NOT NULL CHECK (length(btrim(account)) > 0),
    source       varchar(16) NOT NULL CHECK (source IN ('DIRECTORY', 'FIREWALL')),
    observed_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, address, source)
);

ALTER TABLE scan_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_identities
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
