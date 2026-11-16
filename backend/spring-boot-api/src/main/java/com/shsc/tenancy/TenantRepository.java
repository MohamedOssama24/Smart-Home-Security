package com.shsc.tenancy;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Tenants and organizations (RLS: only the tenant bound to the transaction is visible). */
@Repository
public class TenantRepository {

    public enum TenantType { INDIVIDUAL, BUSINESS, PLATFORM }

    public record Tenant(UUID id, TenantType type, String name, String status, UUID organizationId,
            String organizationName, String planCode) {
    }

    public record Organization(UUID id, String legalName, String vatNumber, String contactEmail,
            String contactPhone, Instant createdAt, Instant updatedAt) {
    }

    public record OrganizationData(String legalName, String vatNumber, String contactEmail, String contactPhone) {
    }

    private static final String ORGANIZATION_COLUMNS =
            "id, legal_name, vat_number, contact_email, contact_phone, created_at, updated_at";

    private final JdbcClient jdbc;

    public TenantRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Inserts the tenant whose id must equal the tenant bound to the transaction. */
    public void insertTenant(UUID id, TenantType type, String name, Instant now) {
        jdbc.sql("INSERT INTO tenants (id, type, name, created_at, updated_at) VALUES (:id, :type, :name, :now, :now)")
                .param("id", id).param("type", type.name()).param("name", name).param("now", Sql.ts(now))
                .update();
    }

    public UUID insertOrganization(UUID tenantId, String legalName, Instant now) {
        return jdbc.sql("""
                INSERT INTO organizations (tenant_id, legal_name, created_at, updated_at)
                VALUES (:tenant, :name, :now, :now) RETURNING id""")
                .param("tenant", tenantId).param("name", legalName).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public Optional<Tenant> current() {
        return jdbc.sql("""
                SELECT t.id, t.type, t.name, t.status, t.plan_code, o.id AS org_id, o.legal_name
                FROM tenants t LEFT JOIN organizations o ON o.tenant_id = t.id""")
                .query((rs, n) -> new Tenant(Sql.uuid(rs, "id"), TenantType.valueOf(rs.getString("type")),
                        rs.getString("name"), rs.getString("status"), Sql.uuid(rs, "org_id"),
                        rs.getString("legal_name"), rs.getString("plan_code")))
                .optional();
    }

    /**
     * Locks the row of the current tenant. Taken before checking a plan limit so that two
     * concurrent creations cannot both pass the check.
     */
    public Optional<Tenant> lockCurrent() {
        return jdbc.sql("SELECT id FROM tenants FOR UPDATE").query(UUID.class).optional()
                .flatMap(id -> current());
    }

    public boolean organizationExists(UUID organizationId) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM organizations WHERE id = :id)")
                .param("id", organizationId).query(Boolean.class).single();
    }

    public Optional<Organization> organization() {
        return jdbc.sql("SELECT " + ORGANIZATION_COLUMNS + " FROM organizations")
                .query((rs, n) -> new Organization(Sql.uuid(rs, "id"), rs.getString("legal_name"),
                        rs.getString("vat_number"), rs.getString("contact_email"), rs.getString("contact_phone"),
                        Sql.instant(rs, "created_at"), Sql.instant(rs, "updated_at")))
                .optional();
    }

    /** Updates the organization and keeps the tenant name aligned with its legal name. */
    public void updateOrganization(UUID tenantId, OrganizationData data, Instant now) {
        jdbc.sql("""
                UPDATE organizations SET legal_name = :name, vat_number = :vat, contact_email = :email,
                    contact_phone = :phone, updated_at = :now
                WHERE tenant_id = :tenant""")
                .param("tenant", tenantId).param("name", data.legalName()).param("vat", data.vatNumber())
                .param("email", data.contactEmail()).param("phone", data.contactPhone()).param("now", Sql.ts(now))
                .update();
        jdbc.sql("UPDATE tenants SET name = :name, updated_at = :now WHERE id = :tenant")
                .param("tenant", tenantId).param("name", data.legalName()).param("now", Sql.ts(now)).update();
    }
}
