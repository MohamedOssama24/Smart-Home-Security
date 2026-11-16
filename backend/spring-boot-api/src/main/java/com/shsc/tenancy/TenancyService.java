package com.shsc.tenancy;

import java.time.Clock;
import java.util.Locale;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits.Plan;
import com.shsc.tenancy.PlanLimits.Usage;
import com.shsc.tenancy.TenantRepository.Organization;
import com.shsc.tenancy.TenantRepository.OrganizationData;
import com.shsc.tenancy.TenantRepository.Tenant;

/** The current tenant (plan, usage) and its organization (BUSINESS tenants only). */
@Service
public class TenancyService {

    /** Tenant, plan and — only for tenant-wide readers — current usage. */
    public record TenantOverview(Tenant tenant, Plan plan, Usage usage) {
    }

    private final TenantRepository tenants;
    private final PlanLimits limits;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public TenancyService(TenantRepository tenants, PlanLimits limits, AccessPolicy access, AuditLog audit,
            Clock clock) {
        this.tenants = tenants;
        this.limits = limits;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public TenantOverview current() {
        AuthenticatedUser user = access.require(Permissions.TENANT_READ);
        Tenant tenant = tenants.current().orElseThrow(ApiException::notFound);
        // users limited to a home or customer do not learn how big the rest of the tenant is
        Usage usage = access.hasTenantWide(user, Permissions.TENANT_READ) ? limits.usage() : null;
        return new TenantOverview(tenant, limits.planOf(tenant), usage);
    }

    @Transactional(readOnly = true)
    public Organization organization() {
        access.require(Permissions.TENANT_READ);
        return tenants.organization().orElseThrow(ApiException::notFound);
    }

    @Transactional
    public Organization updateOrganization(OrganizationData data, ClientInfo client) {
        AuthenticatedUser user = access.requireTenantWide(Permissions.ORGANIZATION_MANAGE);
        tenants.organization().orElseThrow(ApiException::notFound);
        OrganizationData clean = new OrganizationData(data.legalName().trim(), normalizeVat(data.vatNumber()),
                blankToNull(data.contactEmail()), blankToNull(data.contactPhone()));
        tenants.updateOrganization(user.tenantId(), clean, clock.instant());
        audit.record(AuditEvent.of(AuditAction.ORGANIZATION_UPDATED).tenant(user.tenantId()).user(user.userId())
                .target("TENANT", user.tenantId()).client(client).build());
        return tenants.organization().orElseThrow();
    }

    /** VAT numbers are stored without spaces, upper case (e.g. "IT01234567890"). */
    static String normalizeVat(String vat) {
        String value = blankToNull(vat);
        if (value == null) {
            return null;
        }
        String compact = value.replace(" ", "").toUpperCase(Locale.ROOT);
        if (!compact.matches("[A-Z0-9]{2,20}")) {
            throw ApiException.badRequest("INVALID_VAT_NUMBER", "The VAT number is not valid.");
        }
        return compact;
    }

    static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
