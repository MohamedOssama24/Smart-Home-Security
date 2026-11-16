package com.shsc.identity.access;

import java.util.UUID;

/**
 * A role granted to a user on a scope: PLATFORM, TENANT, ORGANIZATION (1:1 with a BUSINESS
 * tenant), a single CUSTOMER of the organization (all its homes) or a single HOME.
 */
public record RoleAssignment(UUID id, String role, ScopeType scopeType, UUID scopeId) {

    public enum ScopeType { PLATFORM, TENANT, ORGANIZATION, CUSTOMER, HOME }

    /** True when the assignment covers every resource of the tenant. */
    public boolean isTenantWide() {
        // ORGANIZATION is 1:1 with a BUSINESS tenant in the MVP
        return scopeType != ScopeType.HOME && scopeType != ScopeType.CUSTOMER;
    }
}
