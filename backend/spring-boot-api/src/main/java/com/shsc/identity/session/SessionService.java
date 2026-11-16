package com.shsc.identity.session;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.RoleAssignment;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.identity.session.SessionRepository.RefreshTokenRow;
import com.shsc.identity.session.SessionRepository.RevokeReason;
import com.shsc.identity.session.SessionRepository.SessionRow;
import com.shsc.identity.token.AccessTokenService;
import com.shsc.identity.token.AccessTokenService.IssuedAccessToken;
import com.shsc.identity.user.UserRecord;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.persistence.SecurityLookups;
import com.shsc.shared.persistence.SecurityLookups.SecretKind;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * Session management: one session per signed-in device, refresh token rotation at every use,
 * detection of reuse of an already rotated token (=> the whole session is revoked).
 */
@Service
public class SessionService {

    public record IssuedSession(UUID sessionId, IssuedAccessToken accessToken, String refreshToken,
            Instant refreshExpiresAt) {
    }

    private sealed interface RotationOutcome permits Rotated, Rejected {
    }

    private record Rotated(IssuedSession session) implements RotationOutcome {
    }

    private record Rejected(String code) implements RotationOutcome {
    }

    private final SessionRepository sessions;
    private final UserRepository users;
    private final RoleAssignmentRepository assignments;
    private final AccessTokenService accessTokens;
    private final SecurityLookups lookups;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final AuditLog audit;
    private final ShscProperties.Session settings;
    private final Clock clock;

    public SessionService(SessionRepository sessions, UserRepository users, RoleAssignmentRepository assignments,
            AccessTokenService accessTokens, SecurityLookups lookups, TenantScope tenantScope,
            TransactionTemplate tx, AuditLog audit, ShscProperties properties, Clock clock) {
        this.sessions = sessions;
        this.users = users;
        this.assignments = assignments;
        this.accessTokens = accessTokens;
        this.lookups = lookups;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.audit = audit;
        this.settings = properties.security().session();
        this.clock = clock;
    }

    /** Opens a new session for an authenticated user. Must run inside a tenant transaction. */
    public IssuedSession open(UserRecord user, ClientInfo client, String deviceLabel) {
        Instant now = clock.instant();
        Instant sessionExpiry = now.plus(settings.maxLifetime());
        UUID sessionId = sessions.insertSession(user.tenantId(), user.id(), deviceLabel, client.userAgent(),
                client.ip(), now, sessionExpiry);
        return issueTokens(user, sessionId, sessionExpiry, now);
    }

    /**
     * Rotates a refresh token. A token that was already used or revoked revokes the whole
     * session (theft detection); the revocation is committed before the 401 is returned.
     */
    public IssuedSession refresh(String rawRefreshToken, ClientInfo client) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw invalidRefresh();
        }
        byte[] hash = SecureTokens.sha256(rawRefreshToken);
        UUID tenantId = lookups.tenantBySecret(SecretKind.REFRESH_TOKEN, hash).orElseThrow(SessionService::invalidRefresh);
        RotationOutcome outcome = tenantScope.callAs(tenantId, () -> tx.execute(status -> rotate(hash, client)));
        if (outcome instanceof Rotated rotated) {
            return rotated.session();
        }
        throw invalidRefresh();
    }

    private RotationOutcome rotate(byte[] hash, ClientInfo client) {
        Instant now = clock.instant();
        Optional<RefreshTokenRow> found = sessions.lockRefreshToken(hash);
        if (found.isEmpty()) {
            return new Rejected("UNKNOWN");
        }
        RefreshTokenRow token = found.get();
        SessionRow session = sessions.lockSession(token.sessionId()).orElseThrow();

        if (token.usedAt() != null || token.revokedAt() != null) {
            if (session.revokedAt() == null) {
                sessions.revokeSession(session.id(), RevokeReason.TOKEN_REUSE, now);
                UUID tenantId = users.findById(session.userId()).map(UserRecord::tenantId).orElse(null);
                audit.record(AuditEvent.of(AuditAction.REFRESH_TOKEN_REUSE).tenant(tenantId).user(session.userId())
                        .failure("REFRESH_TOKEN_REUSED").target("SESSION", session.id()).client(client).build());
            }
            return new Rejected("REUSED");
        }
        if (!token.expiresAt().isAfter(now) || !session.isActive(now)) {
            return new Rejected("EXPIRED");
        }
        UserRecord user = users.findById(session.userId()).orElseThrow();
        if (user.status() != UserRecord.Status.ACTIVE) {
            sessions.revokeSession(session.id(), RevokeReason.ADMIN, now);
            return new Rejected("USER_INACTIVE");
        }
        sessions.markRefreshTokenUsed(token.id(), now);
        sessions.touchSession(session.id(), now, client.ip(), client.userAgent());
        return new Rotated(issueTokens(user, session.id(), session.expiresAt(), now));
    }

    /** Logout with the refresh cookie: revokes the session. Unknown tokens are ignored (idempotent). */
    public void logout(String rawRefreshToken, ClientInfo client) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        byte[] hash = SecureTokens.sha256(rawRefreshToken);
        Optional<UUID> tenantId = lookups.tenantBySecret(SecretKind.REFRESH_TOKEN, hash);
        if (tenantId.isEmpty()) {
            return;
        }
        tenantScope.runAs(tenantId.get(), () -> tx.executeWithoutResult(status -> {
            sessions.lockRefreshToken(hash).flatMap(token -> sessions.lockSession(token.sessionId()))
                    .ifPresent(session -> {
                        if (sessions.revokeSession(session.id(), RevokeReason.LOGOUT, clock.instant())) {
                            audit.record(AuditEvent.of(AuditAction.LOGOUT).tenant(tenantId.get())
                                    .user(session.userId()).target("SESSION", session.id()).client(client).build());
                        }
                    });
        }));
    }

    /** Active sessions of the user (current tenant transaction). */
    public List<SessionRow> listActive(UUID userId) {
        return sessions.listActive(userId, clock.instant());
    }

    /** Revokes one session of the user; 404 if it is not one of theirs. */
    public void revoke(UUID tenantId, UUID userId, UUID sessionId, ClientInfo client) {
        SessionRow session = sessions.lockSession(sessionId)
                .filter(s -> s.userId().equals(userId))
                .orElseThrow(ApiException::notFound);
        if (sessions.revokeSession(session.id(), RevokeReason.USER_REVOKED, clock.instant())) {
            audit.record(AuditEvent.of(AuditAction.SESSION_REVOKED).tenant(tenantId).user(userId)
                    .target("SESSION", sessionId).client(client).build());
        }
    }

    /** Revokes all sessions of the user, optionally keeping {@code keep}. */
    public int revokeAll(UUID tenantId, UUID userId, UUID keep, RevokeReason reason, ClientInfo client) {
        int count = sessions.revokeAllForUser(userId, keep, reason, clock.instant());
        audit.record(AuditEvent.of(AuditAction.SESSIONS_REVOKED_ALL).tenant(tenantId).user(userId)
                .target("USER", userId).client(client).detail("count", count).detail("reason", reason.name())
                .detail("keptCurrent", keep != null).build());
        return count;
    }

    private IssuedSession issueTokens(UserRecord user, UUID sessionId, Instant sessionExpiry, Instant now) {
        String refresh = SecureTokens.generate(SecureTokens.REFRESH_TOKEN_PREFIX);
        Instant refreshExpiry = now.plus(settings.refreshTokenTtl());
        if (refreshExpiry.isAfter(sessionExpiry)) {
            refreshExpiry = sessionExpiry;
        }
        sessions.insertRefreshToken(user.tenantId(), sessionId, SecureTokens.sha256(refresh), now, refreshExpiry);
        List<String> roles = assignments.forUser(user.id()).stream().map(RoleAssignment::role).distinct().toList();
        IssuedAccessToken access = accessTokens.issue(user.id(), user.tenantId(), sessionId, roles);
        return new IssuedSession(sessionId, access, refresh, refreshExpiry);
    }

    private static ApiException invalidRefresh() {
        return ApiException.unauthorized("INVALID_REFRESH_TOKEN", "The session is not valid. Please sign in again.");
    }
}
