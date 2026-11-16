package com.shsc.identity.access;

import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.web.ApiException;

/**
 * Central authorization decisions (always on the server). A request is allowed when
 * <em>role grants the permission ∧ resource is inside the assignment scope ∧ resource belongs
 * to the tenant</em>. The tenant part is also enforced by PostgreSQL RLS: a resource of
 * another tenant is simply not found (404), so changing an ID in the URL reveals nothing.
 * <p>
 * Scopes: TENANT / ORGANIZATION cover the whole tenant; CUSTOMER covers the customer and all
 * its homes; HOME covers one home. Home checks must run inside a transaction (the customer
 * of the home is read from the database, under RLS).
 */
@Component
public class AccessPolicy {

    private final RoleCatalog catalog;
    private final HomeRepository homes;

    public AccessPolicy(RoleCatalog catalog, HomeRepository homes) {
        this.catalog = catalog;
        this.homes = homes;
    }

    public AuthenticatedUser currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof UserAuthentication user) {
            return user.getPrincipal();
        }
        throw new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Authentication is required.");
    }

    /** All permissions the user holds on at least one scope. */
    public Set<String> effectivePermissions(AuthenticatedUser user) {
        Set<String> result = new TreeSet<>();
        user.assignments().forEach(a -> result.addAll(catalog.permissionsOf(a.role())));
        return result;
    }

    public boolean hasTenantWide(AuthenticatedUser user, String permission) {
        return user.assignments().stream()
                .anyMatch(a -> a.isTenantWide() && grants(a, permission));
    }

    public boolean hasOnHome(AuthenticatedUser user, String permission, UUID homeId) {
        boolean direct = user.assignments().stream()
                .filter(a -> grants(a, permission))
                .anyMatch(a -> a.isTenantWide() || (a.scopeType() == ScopeType.HOME && homeId.equals(a.scopeId())));
        if (direct) {
            return true;
        }
        Set<UUID> customers = customerScopes(user, permission);
        if (customers.isEmpty()) {
            return false;
        }
        Optional<UUID> customer = homes.customerOf(homeId);
        return customer.isPresent() && customers.contains(customer.get());
    }

    public boolean hasOnCustomer(AuthenticatedUser user, String permission, UUID customerId) {
        return hasTenantWide(user, permission) || customerScopes(user, permission).contains(customerId);
    }

    /** Homes explicitly assigned through HOME-scoped roles granting {@code permission}. */
    public Set<UUID> homeScopes(AuthenticatedUser user, String permission) {
        return scopes(user, permission, ScopeType.HOME);
    }

    /** Customers assigned through CUSTOMER-scoped roles granting {@code permission}. */
    public Set<UUID> customerScopes(AuthenticatedUser user, String permission) {
        return scopes(user, permission, ScopeType.CUSTOMER);
    }

    /** 403 if the user has the permission on no scope at all. */
    public AuthenticatedUser require(String permission) {
        AuthenticatedUser user = currentUser();
        boolean any = user.assignments().stream().anyMatch(a -> grants(a, permission));
        if (!any) {
            throw ApiException.forbidden();
        }
        return user;
    }

    /** 403 unless the permission is held on the whole tenant. */
    public AuthenticatedUser requireTenantWide(String permission) {
        AuthenticatedUser user = currentUser();
        if (!hasTenantWide(user, permission)) {
            throw ApiException.forbidden();
        }
        return user;
    }

    /**
     * For an existing home of the tenant: 404 when the home is outside every scope of the
     * user (no information disclosure), 403 when visible but the permission is missing.
     */
    public AuthenticatedUser requireOnHome(String permission, UUID homeId) {
        AuthenticatedUser user = currentUser();
        if (hasOnHome(user, permission, homeId)) {
            return user;
        }
        boolean visible = hasOnHome(user, Permissions.HOME_READ, homeId);
        throw visible ? ApiException.forbidden() : ApiException.notFound();
    }

    /** Same as {@link #requireOnHome} for an existing customer of the tenant. */
    public AuthenticatedUser requireOnCustomer(String permission, UUID customerId) {
        AuthenticatedUser user = currentUser();
        if (hasOnCustomer(user, permission, customerId)) {
            return user;
        }
        boolean visible = hasOnCustomer(user, Permissions.CUSTOMER_READ, customerId);
        throw visible ? ApiException.forbidden() : ApiException.notFound();
    }

    private boolean grants(RoleAssignment assignment, String permission) {
        return catalog.permissionsOf(assignment.role()).contains(permission);
    }

    private Set<UUID> scopes(AuthenticatedUser user, String permission, ScopeType type) {
        Set<UUID> ids = new TreeSet<>();
        user.assignments().stream()
                .filter(a -> a.scopeType() == type)
                .filter(a -> grants(a, permission))
                .forEach(a -> ids.add(a.scopeId()));
        return ids;
    }
}
