package com.shsc.customers;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.customers.CustomerRepository.Customer;
import com.shsc.customers.CustomerRepository.CustomerData;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;
import com.shsc.tenancy.TenantRepository;
import com.shsc.tenancy.TenantRepository.TenantType;

/**
 * Customers of an organization (B2B only). Managers need {@code customer:manage} on the
 * whole tenant; readers see every customer (tenant-wide {@code customer:read}) or only the
 * customers they are assigned to (CUSTOMER scope). Archiving is refused while the customer
 * still has homes, so no home is left pointing to an archived customer.
 */
@Service
public class CustomerService {

    private final CustomerRepository customers;
    private final HomeRepository homes;
    private final TenantRepository tenants;
    private final PlanLimits limits;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public CustomerService(CustomerRepository customers, HomeRepository homes, TenantRepository tenants,
            PlanLimits limits, AccessPolicy access, AuditLog audit, Clock clock) {
        this.customers = customers;
        this.homes = homes;
        this.tenants = tenants;
        this.limits = limits;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public Customer create(CustomerData data, ClientInfo client) {
        AuthenticatedUser user = access.requireTenantWide(Permissions.CUSTOMER_MANAGE);
        requireBusinessTenant();
        limits.requireCapacity(Resource.CUSTOMERS, null);
        Customer customer = customers.insert(user.tenantId(), clean(data), user.userId(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.CUSTOMER_CREATED).tenant(user.tenantId()).user(user.userId())
                .target("CUSTOMER", customer.id()).client(client).build());
        return customer;
    }

    @Transactional(readOnly = true)
    public List<Customer> list() {
        AuthenticatedUser user = access.require(Permissions.CUSTOMER_READ);
        if (access.hasTenantWide(user, Permissions.CUSTOMER_READ)) {
            return customers.findAll();
        }
        return customers.findByIds(access.customerScopes(user, Permissions.CUSTOMER_READ));
    }

    @Transactional(readOnly = true)
    public Customer get(UUID id) {
        Customer customer = customers.find(id).orElseThrow(ApiException::notFound);
        access.requireOnCustomer(Permissions.CUSTOMER_READ, id);
        return customer;
    }

    @Transactional
    public Customer update(UUID id, CustomerData data, ClientInfo client) {
        customers.lock(id).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = requireManage(id);
        Customer updated = customers.update(id, clean(data), clock.instant());
        audit.record(AuditEvent.of(AuditAction.CUSTOMER_UPDATED).tenant(user.tenantId()).user(user.userId())
                .target("CUSTOMER", id).client(client).build());
        return updated;
    }

    @Transactional
    public void archive(UUID id, ClientInfo client) {
        customers.lock(id).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = requireManage(id);
        if (homes.countActiveOfCustomer(id) > 0) {
            throw ApiException.conflict("CUSTOMER_HAS_HOMES",
                    "Move or archive the homes of this customer before archiving it.");
        }
        Instant now = clock.instant();
        customers.archive(id, now);
        audit.record(AuditEvent.of(AuditAction.CUSTOMER_ARCHIVED).tenant(user.tenantId()).user(user.userId())
                .target("CUSTOMER", id).client(client).build());
    }

    /** 404 for customers the user cannot see, 403 for visible ones without the permission. */
    private AuthenticatedUser requireManage(UUID id) {
        AuthenticatedUser user = access.requireOnCustomer(Permissions.CUSTOMER_READ, id);
        if (!access.hasTenantWide(user, Permissions.CUSTOMER_MANAGE)) {
            throw ApiException.forbidden();
        }
        return user;
    }

    private void requireBusinessTenant() {
        TenantType type = tenants.current().orElseThrow(ApiException::notFound).type();
        if (type != TenantType.BUSINESS) {
            throw new ApiException(HttpStatus.CONFLICT, "BUSINESS_TENANT_REQUIRED",
                    "Customers are available only for business accounts.");
        }
    }

    private static CustomerData clean(CustomerData data) {
        return new CustomerData(data.displayName().trim(), blankToNull(data.contactEmail()),
                blankToNull(data.contactPhone()), blankToNull(data.notes()));
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
