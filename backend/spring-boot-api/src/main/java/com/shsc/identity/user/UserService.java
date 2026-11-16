package com.shsc.identity.user;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.authentication.ActionTokenRepository;
import com.shsc.identity.authentication.ActionTokenRepository.Purpose;
import com.shsc.identity.mail.AccountMailer;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.identity.role.RoleAssignmentRepository.StoredAssignment;
import com.shsc.identity.role.RoleService;
import com.shsc.identity.session.SessionRepository;
import com.shsc.identity.session.SessionRepository.RevokeReason;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.persistence.SecurityLookups;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;
import com.shsc.tenancy.TenantRepository;

/**
 * Users of the tenant, managed by holders of {@code user:manage} on the whole tenant.
 * <ul>
 * <li>Invitation: creates the user without a password, grants the first role (same rules as
 * role management: no escalation, no platform roles) and e-mails a one-time link with which
 * the user chooses the password. Nobody else ever knows the password.</li>
 * <li>Disabling: the user can no longer sign in, every session is revoked at once, pending
 * e-mail links stop working. Roles are kept for a later re-activation. There is no physical
 * deletion: the audit log keeps referring to the user.</li>
 * <li>Guards: an administrator cannot disable themselves, the last enabled organization
 * administrator cannot be disabled, plan limits apply to invitations and re-activations.</li>
 * </ul>
 */
@Service
public class UserService {

    private static final String ORGANIZATION_ADMIN = "ORGANIZATION_ADMIN";

    public record Invitation(String email, String displayName, String locale, String role, ScopeType scopeType,
            UUID scopeId) {
    }

    public record UserView(UserRecord user, List<StoredAssignment> roles) {

        public boolean invitationPending() {
            return user.passwordHash() == null && user.status() != UserRecord.Status.DISABLED;
        }
    }

    private final UserRepository users;
    private final RoleAssignmentRepository assignments;
    private final RoleService roles;
    private final ActionTokenRepository actionTokens;
    private final SessionRepository sessions;
    private final SecurityLookups lookups;
    private final TenantRepository tenants;
    private final PlanLimits limits;
    private final AccountMailer mailer;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final ShscProperties.Tokens tokenSettings;
    private final Clock clock;

    public UserService(UserRepository users, RoleAssignmentRepository assignments, RoleService roles,
            ActionTokenRepository actionTokens, SessionRepository sessions, SecurityLookups lookups,
            TenantRepository tenants, PlanLimits limits, AccountMailer mailer, AccessPolicy access, AuditLog audit,
            ShscProperties properties, Clock clock) {
        this.users = users;
        this.assignments = assignments;
        this.roles = roles;
        this.actionTokens = actionTokens;
        this.sessions = sessions;
        this.lookups = lookups;
        this.tenants = tenants;
        this.limits = limits;
        this.mailer = mailer;
        this.access = access;
        this.audit = audit;
        this.tokenSettings = properties.security().tokens();
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<UserView> list() {
        access.requireTenantWide(Permissions.USER_READ);
        Map<UUID, List<StoredAssignment>> byUser = assignments.all().stream()
                .collect(Collectors.groupingBy(StoredAssignment::userId));
        return users.findAll().stream().map(u -> new UserView(u, byUser.getOrDefault(u.id(), List.of()))).toList();
    }

    @Transactional(readOnly = true)
    public UserView get(UUID userId) {
        access.requireTenantWide(Permissions.USER_READ);
        UserRecord user = users.findById(userId).orElseThrow(ApiException::notFound);
        return new UserView(user, assignments.detailedForUser(userId));
    }

    @Transactional
    public UserView invite(Invitation invitation, ClientInfo client) {
        AuthenticatedUser actor = access.requireTenantWide(Permissions.USER_MANAGE);
        String email = invitation.email().trim().toLowerCase(Locale.ROOT);
        if (lookups.userByEmail(email).isPresent()) {
            throw emailUnavailable();
        }
        limits.requireCapacity(Resource.USERS, null);
        Instant now = clock.instant();
        String locale = "en".equals(invitation.locale()) ? "en" : "it";
        String displayName = invitation.displayName().trim();
        UUID userId;
        try {
            userId = users.insertInvited(actor.tenantId(), email, displayName, locale, now);
        } catch (DuplicateKeyException race) {
            throw emailUnavailable();
        }
        // same checks as POST /users/{id}/roles: role:manage, valid scope, no privilege escalation
        roles.assign(userId, invitation.role(), invitation.scopeType(), invitation.scopeId(), client);
        sendInvitation(actor, userId, email, locale, displayName, now);
        audit.record(AuditEvent.of(AuditAction.USER_INVITED).tenant(actor.tenantId()).user(actor.userId())
                .target("USER", userId).client(client).detail("role", invitation.role())
                .detail("scopeType", invitation.scopeType().name()).detail("scopeId", invitation.scopeId()).build());
        return get(userId);
    }

    /** Sends a new invitation link (the previous one stops working). */
    @Transactional
    public void resendInvitation(UUID userId, ClientInfo client) {
        AuthenticatedUser actor = access.requireTenantWide(Permissions.USER_MANAGE);
        UserRecord user = users.lockById(userId).orElseThrow(ApiException::notFound);
        if (user.passwordHash() != null || user.status() == UserRecord.Status.DISABLED) {
            throw ApiException.conflict("INVITATION_NOT_PENDING", "The user has already accepted the invitation.");
        }
        sendInvitation(actor, userId, user.email(), user.locale(), user.displayName(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.USER_INVITATION_RESENT).tenant(actor.tenantId()).user(actor.userId())
                .target("USER", userId).client(client).build());
    }

    /** Changes the display name and/or enables / disables the user ({@code null} = unchanged). */
    @Transactional
    public UserView update(UUID userId, String displayName, UserRecord.Status status, ClientInfo client) {
        AuthenticatedUser actor = access.requireTenantWide(Permissions.USER_MANAGE);
        UserRecord user = users.lockById(userId).orElseThrow(ApiException::notFound);
        if (status == UserRecord.Status.PENDING_VERIFICATION) {
            throw ApiException.badRequest("INVALID_STATUS", "Only ACTIVE or DISABLED can be requested.");
        }
        Instant now = clock.instant();
        if (displayName != null && !displayName.trim().equals(user.displayName())) {
            users.updateDisplayName(userId, displayName.trim(), now);
            audit.record(AuditEvent.of(AuditAction.USER_UPDATED).tenant(actor.tenantId()).user(actor.userId())
                    .target("USER", userId).client(client).build());
        }
        if (status == UserRecord.Status.DISABLED && user.status() != UserRecord.Status.DISABLED) {
            disable(actor, user, now, client);
        } else if (status == UserRecord.Status.ACTIVE && user.status() == UserRecord.Status.DISABLED) {
            limits.requireCapacity(Resource.USERS, null);
            users.enable(userId, now);
            audit.record(AuditEvent.of(AuditAction.USER_ENABLED).tenant(actor.tenantId()).user(actor.userId())
                    .target("USER", userId).client(client).build());
        }
        return get(userId);
    }

    private void disable(AuthenticatedUser actor, UserRecord user, Instant now, ClientInfo client) {
        if (user.id().equals(actor.userId())) {
            throw ApiException.conflict("CANNOT_DISABLE_SELF", "You cannot disable your own account.");
        }
        boolean tenantAdmin = assignments.detailedForUser(user.id()).stream()
                .anyMatch(a -> ORGANIZATION_ADMIN.equals(a.assignment().role()) && a.assignment().isTenantWide());
        if (tenantAdmin && assignments.countTenantWideHolders(ORGANIZATION_ADMIN) <= 1) {
            throw ApiException.conflict("LAST_ADMIN", "The last organization administrator cannot be disabled.");
        }
        users.disable(user.id(), now);
        int revoked = sessions.revokeAllForUser(user.id(), null, RevokeReason.ADMIN, now);
        actionTokens.invalidateAll(user.id(), now);
        audit.record(AuditEvent.of(AuditAction.USER_DISABLED).tenant(actor.tenantId()).user(actor.userId())
                .target("USER", user.id()).client(client).detail("revokedSessions", revoked).build());
    }

    private void sendInvitation(AuthenticatedUser actor, UUID userId, String email, String locale, String displayName,
            Instant now) {
        String token = SecureTokens.generate(SecureTokens.EMAIL_TOKEN_PREFIX);
        actionTokens.replace(actor.tenantId(), userId, Purpose.INVITATION, SecureTokens.sha256(token), now,
                now.plus(tokenSettings.invitationTtl()));
        String organization = tenants.current().orElseThrow(ApiException::notFound).name();
        mailer.invitation(email, locale, displayName, actor.displayName(), organization, token,
                Math.max(1, tokenSettings.invitationTtl().toDays()));
    }

    private static ApiException emailUnavailable() {
        return ApiException.conflict("EMAIL_ALREADY_REGISTERED", "This e-mail address already has an account.");
    }
}
