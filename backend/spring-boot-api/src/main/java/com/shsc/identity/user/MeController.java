package com.shsc.identity.user;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.RoleAssignment;
import com.shsc.identity.password.PasswordChangeService;
import com.shsc.identity.session.SessionRepository.RevokeReason;
import com.shsc.identity.session.SessionRepository.SessionRow;
import com.shsc.identity.session.SessionService;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.TenantRepository;
import com.shsc.tenancy.TenantRepository.Tenant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** The signed-in user: profile, password, sessions (one per device). */
@RestController
@RequestMapping("/api/v1/me")
public class MeController {

    public record TenantSummary(UUID id, String type, String name, UUID organizationId) {
    }

    public record MeResponse(UUID id, String email, String displayName, String locale, String status,
            Instant emailVerifiedAt, TenantSummary tenant, List<RoleAssignment> roles, Set<String> permissions,
            UUID sessionId) {
    }

    public record UpdateProfileRequest(@NotBlank @Size(max = 100) String displayName,
            @NotBlank @Pattern(regexp = "it|en") String locale) {
    }

    public record ChangePasswordRequest(@NotBlank @Size(max = 1024) String currentPassword,
            @NotBlank @Size(max = 1024) String newPassword) {
    }

    public record SessionResponse(UUID id, String deviceLabel, String userAgent, String ipAddress,
            Instant createdAt, Instant lastUsedAt, Instant expiresAt, boolean current) {
    }

    public record RevokeAllRequest(boolean includeCurrent) {
    }

    public record RevokeAllResponse(int revoked) {
    }

    private final AccessPolicy access;
    private final UserRepository users;
    private final TenantRepository tenants;
    private final PasswordChangeService passwords;
    private final SessionService sessions;
    private final AuditLog audit;
    private final TransactionTemplate tx;
    private final Clock clock;

    public MeController(AccessPolicy access, UserRepository users, TenantRepository tenants,
            PasswordChangeService passwords, SessionService sessions, AuditLog audit, TransactionTemplate tx,
            Clock clock) {
        this.access = access;
        this.users = users;
        this.tenants = tenants;
        this.passwords = passwords;
        this.sessions = sessions;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
    }

    @GetMapping
    public MeResponse me() {
        AuthenticatedUser principal = access.currentUser();
        return tx.execute(s -> {
            UserRecord user = users.findById(principal.userId()).orElseThrow(ApiException::notFound);
            Tenant tenant = tenants.current().orElseThrow(ApiException::notFound);
            return new MeResponse(user.id(), user.email(), user.displayName(), user.locale(), user.status().name(),
                    user.emailVerifiedAt(),
                    new TenantSummary(tenant.id(), tenant.type().name(), tenant.name(), tenant.organizationId()),
                    principal.assignments(), access.effectivePermissions(principal), principal.sessionId());
        });
    }

    @PatchMapping
    public MeResponse updateProfile(@Valid @RequestBody UpdateProfileRequest request, HttpServletRequest http) {
        AuthenticatedUser principal = access.currentUser();
        tx.executeWithoutResult(s -> {
            users.updateProfile(principal.userId(), request.displayName().trim(), request.locale(), clock.instant());
            audit.record(AuditEvent.of(AuditAction.PROFILE_UPDATED).tenant(principal.tenantId())
                    .user(principal.userId()).target("USER", principal.userId()).client(ClientInfo.from(http))
                    .build());
        });
        return me();
    }

    @PostMapping("/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@Valid @RequestBody ChangePasswordRequest request, HttpServletRequest http) {
        passwords.change(access.currentUser(), request.currentPassword(), request.newPassword(), ClientInfo.from(http));
    }

    @GetMapping("/sessions")
    public List<SessionResponse> sessions() {
        AuthenticatedUser principal = access.currentUser();
        List<SessionRow> rows = tx.execute(s -> sessions.listActive(principal.userId()));
        return rows.stream().map(row -> new SessionResponse(row.id(), row.deviceLabel(), row.userAgent(),
                row.ipAddress(), row.createdAt(), row.lastUsedAt(), row.expiresAt(),
                row.id().equals(principal.sessionId()))).toList();
    }

    @DeleteMapping("/sessions/{sessionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revokeSession(@PathVariable UUID sessionId, HttpServletRequest http) {
        AuthenticatedUser principal = access.currentUser();
        tx.executeWithoutResult(s -> sessions.revoke(principal.tenantId(), principal.userId(), sessionId,
                ClientInfo.from(http)));
    }

    /** Revokes every session of the user ("sign out everywhere"), optionally keeping this one. */
    @PostMapping("/sessions/revoke-all")
    public RevokeAllResponse revokeAll(@RequestBody(required = false) RevokeAllRequest request,
            HttpServletRequest http) {
        AuthenticatedUser principal = access.currentUser();
        boolean includeCurrent = request == null || request.includeCurrent();
        UUID keep = includeCurrent ? null : principal.sessionId();
        int revoked = tx.execute(s -> sessions.revokeAll(principal.tenantId(), principal.userId(), keep,
                RevokeReason.REVOKE_ALL, ClientInfo.from(http)));
        return new RevokeAllResponse(revoked);
    }
}
