package com.shsc.identity.role;

import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.customers.CustomerRepository;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.access.RoleCatalog;
import com.shsc.identity.access.RoleCatalog.RoleDefinition;
import com.shsc.identity.role.RoleAssignmentRepository.StoredAssignment;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.TenantRepository;

/**
 * Role management inside a tenant. Rules: only holders of {@code role:manage} (tenant-wide);
 * SUPER_ADMIN / PLATFORM scope can never be granted through the API; a role can be granted
 * only if the granter already holds all of its permissions (no privilege escalation); the
 * last tenant-wide ORGANIZATION_ADMIN cannot be removed. Every change is audited and takes
 * effect at the next request (permissions are re-read for every request).
 */
@Service
public class RoleService {

    private static final String ORGANIZATION_ADMIN = "ORGANIZATION_ADMIN";

    private final RoleAssignmentRepository assignments;
    private final RoleCatalog catalog;
    private final UserRepository users;
    private final HomeRepository homes;
    private final CustomerRepository customers;
    private final TenantRepository tenants;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public RoleService(RoleAssignmentRepository assignments, RoleCatalog catalog, UserRepository users,
            HomeRepository homes, CustomerRepository customers, TenantRepository tenants, AccessPolicy access,
            AuditLog audit, Clock clock) {
        this.assignments = assignments;
        this.catalog = catalog;
        this.users = users;
        this.homes = homes;
        this.customers = customers;
        this.tenants = tenants;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<StoredAssignment> list(UUID userId) {
        access.requireTenantWide(Permissions.USER_READ);
        users.findById(userId).orElseThrow(ApiException::notFound);
        return assignments.detailedForUser(userId);
    }

    @Transactional
    public UUID assign(UUID userId, String roleCode, ScopeType scopeType, UUID scopeId, ClientInfo client) {
        AuthenticatedUser actor = access.requireTenantWide(Permissions.ROLE_MANAGE);
        users.findById(userId).orElseThrow(ApiException::notFound);

        RoleDefinition role = catalog.find(roleCode);
        if (role == null) {
            throw ApiException.badRequest("UNKNOWN_ROLE", "Unknown role.");
        }
        if (scopeType == ScopeType.PLATFORM || role.permissions().contains(Permissions.PLATFORM_ADMIN)) {
            throw ApiException.forbidden();
        }
        if (!role.assignableScopes().contains(scopeType)) {
            throw ApiException.badRequest("INVALID_SCOPE", "This role cannot be assigned on that scope.");
        }
        switch (scopeType) {
            case TENANT -> {
                if (scopeId != null) {
                    throw ApiException.badRequest("INVALID_SCOPE", "A tenant scope has no identifier.");
                }
            }
            case ORGANIZATION -> {
                if (scopeId == null || !tenants.organizationExists(scopeId)) {
                    throw ApiException.badRequest("INVALID_SCOPE", "Unknown organization.");
                }
            }
            case CUSTOMER -> {
                if (scopeId == null || customers.find(scopeId).isEmpty()) {
                    throw ApiException.badRequest("INVALID_SCOPE", "Unknown customer.");
                }
            }
            case HOME -> {
                if (scopeId == null || homes.find(scopeId).isEmpty()) {
                    throw ApiException.badRequest("INVALID_SCOPE", "Unknown home.");
                }
            }
            case PLATFORM -> throw ApiException.forbidden();
        }
        Set<String> actorPermissions = access.effectivePermissions(actor);
        if (!actorPermissions.containsAll(role.permissions())) {
            throw ApiException.forbidden();
        }
        UUID id;
        try {
            id = assignments.insert(actor.tenantId(), userId, roleCode, scopeType, scopeId, actor.userId(),
                    clock.instant());
        } catch (DuplicateKeyException e) {
            throw ApiException.conflict("ROLE_ALREADY_ASSIGNED", "The user already has this role on this scope.");
        }
        audit.record(AuditEvent.of(AuditAction.ROLE_ASSIGNED).tenant(actor.tenantId()).user(actor.userId())
                .target("USER", userId).client(client).detail("assignmentId", id).detail("role", roleCode)
                .detail("scopeType", scopeType.name()).detail("scopeId", scopeId).build());
        return id;
    }

    @Transactional
    public void revoke(UUID userId, UUID assignmentId, ClientInfo client) {
        AuthenticatedUser actor = access.requireTenantWide(Permissions.ROLE_MANAGE);
        StoredAssignment assignment = assignments.lock(assignmentId)
                .filter(a -> a.userId().equals(userId))
                .orElseThrow(ApiException::notFound);
        String role = assignment.assignment().role();
        if (ORGANIZATION_ADMIN.equals(role) && assignment.assignment().isTenantWide()
                && assignments.countTenantWideHolders(ORGANIZATION_ADMIN) <= 1
                && assignments.detailedForUser(userId).stream().filter(a -> ORGANIZATION_ADMIN.equals(a.assignment().role())
                        && a.assignment().isTenantWide()).count() <= 1) {
            throw ApiException.conflict("LAST_ADMIN", "The last organization administrator cannot be removed.");
        }
        assignments.delete(assignmentId);
        audit.record(AuditEvent.of(AuditAction.ROLE_REVOKED).tenant(actor.tenantId()).user(actor.userId())
                .target("USER", userId).client(client).detail("assignmentId", assignmentId).detail("role", role)
                .detail("scopeType", assignment.assignment().scopeType().name())
                .detail("scopeId", assignment.assignment().scopeId()).build());
    }

    public List<RoleDefinition> catalogue() {
        access.currentUser();
        return catalog.all();
    }
}
