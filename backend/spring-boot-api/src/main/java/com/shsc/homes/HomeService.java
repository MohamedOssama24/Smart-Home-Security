package com.shsc.homes;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.agents.management.AgentRepository;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.customers.CustomerRepository;
import com.shsc.homes.HomeRepository.Home;
import com.shsc.homes.HomeRepository.HomeData;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;

/**
 * Homes of the tenant.
 * <ul>
 * <li>Create / archive / move to another customer: "owner" level, i.e. {@code home:write} on
 * the whole tenant, or on the customer the home belongs to (CUSTOMER scope).</li>
 * <li>Edit name, address, time zone: {@code home:write} on the home (HOME scope is enough).</li>
 * <li>A home with active agents cannot be archived: agents must be revoked first.</li>
 * </ul>
 */
@Service
public class HomeService {

    public static final String DEFAULT_TIMEZONE = "Europe/Rome";

    private final HomeRepository homes;
    private final CustomerRepository customers;
    private final AgentRepository agents;
    private final PlanLimits limits;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public HomeService(HomeRepository homes, CustomerRepository customers, AgentRepository agents, PlanLimits limits,
            AccessPolicy access, AuditLog audit, Clock clock) {
        this.homes = homes;
        this.customers = customers;
        this.agents = agents;
        this.limits = limits;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public Home create(HomeData request, ClientInfo client) {
        AuthenticatedUser user = access.require(Permissions.HOME_WRITE);
        HomeData data = clean(request);
        requireCustomer(data.customerId());
        if (!canOwn(user, data.customerId())) {
            throw ApiException.forbidden();
        }
        limits.requireCapacity(Resource.HOMES, null);
        Home home = homes.insert(user.tenantId(), data, user.userId(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.HOME_CREATED).tenant(user.tenantId()).user(user.userId())
                .target("HOME", home.id()).client(client).detail("customerId", home.customerId()).build());
        return home;
    }

    /** Homes visible to the user (whole tenant, assigned customers, assigned homes). */
    @Transactional(readOnly = true)
    public List<Home> list(UUID customerId) {
        AuthenticatedUser user = access.require(Permissions.HOME_READ);
        if (access.hasTenantWide(user, Permissions.HOME_READ)) {
            return homes.findAll(customerId);
        }
        return homes.findVisible(access.homeScopes(user, Permissions.HOME_READ),
                access.customerScopes(user, Permissions.HOME_READ), customerId);
    }

    @Transactional(readOnly = true)
    public Home get(UUID homeId) {
        Home home = homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.HOME_READ, home.id());
        return home;
    }

    @Transactional
    public Home update(UUID homeId, HomeData request, ClientInfo client) {
        Home current = homes.lock(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.HOME_WRITE, homeId);
        HomeData data = clean(request);
        boolean moved = !Objects.equals(current.customerId(), data.customerId());
        if (moved) {
            requireCustomer(data.customerId());
            // moving a home needs owner rights on both the old and the new customer
            if (!canOwn(user, current.customerId()) || !canOwn(user, data.customerId())) {
                throw ApiException.forbidden();
            }
        }
        Home updated = homes.update(homeId, data, clock.instant());
        AuditEvent.Builder event = AuditEvent.of(AuditAction.HOME_UPDATED).tenant(user.tenantId()).user(user.userId())
                .target("HOME", homeId).client(client);
        if (moved) {
            event.detail("fromCustomerId", current.customerId()).detail("toCustomerId", data.customerId());
        }
        audit.record(event.build());
        return updated;
    }

    @Transactional
    public void archive(UUID homeId, ClientInfo client) {
        Home home = homes.lock(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.HOME_WRITE, homeId);
        if (!canOwn(user, home.customerId())) {
            throw ApiException.forbidden();
        }
        boolean activeAgents = agents.forHome(homeId).stream()
                .anyMatch(a -> a.status() == AgentRepository.AgentStatus.ACTIVE);
        if (activeAgents) {
            throw ApiException.conflict("HOME_HAS_ACTIVE_AGENTS", "Revoke the agents of this home before archiving it.");
        }
        homes.archive(homeId, clock.instant());
        audit.record(AuditEvent.of(AuditAction.HOME_ARCHIVED).tenant(user.tenantId()).user(user.userId())
                .target("HOME", homeId).client(client).build());
    }

    private boolean canOwn(AuthenticatedUser user, UUID customerId) {
        return access.hasTenantWide(user, Permissions.HOME_WRITE)
                || (customerId != null && access.customerScopes(user, Permissions.HOME_WRITE).contains(customerId));
    }

    private void requireCustomer(UUID customerId) {
        if (customerId != null && customers.find(customerId).isEmpty()) {
            throw ApiException.badRequest("INVALID_CUSTOMER", "Unknown customer.");
        }
    }

    private static HomeData clean(HomeData data) {
        String timezone = data.timezone() == null || data.timezone().isBlank() ? DEFAULT_TIMEZONE : data.timezone().trim();
        try {
            ZoneId.of(timezone);
        } catch (DateTimeException e) {
            throw ApiException.badRequest("INVALID_TIMEZONE", "Unknown time zone.");
        }
        String address = data.address() == null || data.address().isBlank() ? null : data.address().trim();
        return new HomeData(data.name().trim(), data.customerId(), address, timezone);
    }
}
