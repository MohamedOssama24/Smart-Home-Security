-- Deletion of scans and of the inventory of a home (docs/05-API.md §Scans, ADR-082).
-- Destructive: only the owner and the administrators of the tenant (not technicians, not read-only).
INSERT INTO permissions (code, description) VALUES
    ('scan:delete', 'Delete a finished scan or all the scans and the inventory of a home');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'scan:delete'), ('ORGANIZATION_ADMIN', 'scan:delete'), ('CUSTOMER', 'scan:delete');
