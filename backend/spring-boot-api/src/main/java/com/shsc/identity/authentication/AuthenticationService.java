package com.shsc.identity.authentication;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.authentication.ActionTokenRepository.ActionToken;
import com.shsc.identity.authentication.ActionTokenRepository.Purpose;
import com.shsc.identity.mail.AccountMailer;
import com.shsc.identity.password.PasswordPolicy;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.identity.session.SessionRepository.RevokeReason;
import com.shsc.identity.session.SessionRepository;
import com.shsc.identity.session.SessionService;
import com.shsc.identity.session.SessionService.IssuedSession;
import com.shsc.identity.user.UserRecord;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.persistence.SecurityLookups;
import com.shsc.shared.persistence.SecurityLookups.SecretKind;
import com.shsc.shared.persistence.SecurityLookups.UserRef;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.TenantRepository;
import com.shsc.tenancy.TenantRepository.TenantType;

/**
 * Password based authentication: registration, e-mail verification, login, password reset.
 * <p>
 * Anti-enumeration: registration, resend and "forgot password" always answer the same way;
 * login answers {@code INVALID_CREDENTIALS} for unknown e-mail, wrong password and disabled
 * account alike, runs a full Argon2id verification also for unknown e-mails (same timing)
 * and throttles by hashed e-mail whether or not the account exists.
 * <p>
 * Extension points: the primary credential check ({@link #verifyPassword}) is separate from
 * session issuance ({@link SessionService#open}); MFA (M3+) inserts a challenge step
 * between them, OIDC (future) is another primary authenticator issuing the same session.
 */
@Service
public class AuthenticationService {

    public enum AccountType { INDIVIDUAL, BUSINESS }

    public record Registration(String email, String password, String displayName, String locale,
            AccountType accountType, String organizationName) {
    }

    public record LoginResult(IssuedSession session, UserRecord user) {
    }

    private static final String LOGIN = "login";
    private static final String MAIL = "mail";

    private final UserRepository users;
    private final TenantRepository tenants;
    private final RoleAssignmentRepository assignments;
    private final ActionTokenRepository actionTokens;
    private final SessionRepository sessionRepository;
    private final SessionService sessions;
    private final SecurityLookups lookups;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final PasswordEncoder encoder;
    private final PasswordPolicy policy;
    private final AuthThrottle throttle;
    private final AccountMailer mailer;
    private final AuditLog audit;
    private final ShscProperties.Tokens tokenSettings;
    private final Clock clock;
    private final String timingHash;

    public AuthenticationService(UserRepository users, TenantRepository tenants, RoleAssignmentRepository assignments,
            ActionTokenRepository actionTokens, SessionRepository sessionRepository, SessionService sessions,
            SecurityLookups lookups, TenantScope tenantScope, TransactionTemplate tx, PasswordEncoder encoder,
            PasswordPolicy policy, AuthThrottle throttle, AccountMailer mailer, AuditLog audit,
            ShscProperties properties, Clock clock) {
        this.users = users;
        this.tenants = tenants;
        this.assignments = assignments;
        this.actionTokens = actionTokens;
        this.sessionRepository = sessionRepository;
        this.sessions = sessions;
        this.lookups = lookups;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.encoder = encoder;
        this.policy = policy;
        this.throttle = throttle;
        this.mailer = mailer;
        this.audit = audit;
        this.tokenSettings = properties.security().tokens();
        this.clock = clock;
        // hash used to spend the same time verifying a password when the e-mail is unknown
        this.timingHash = encoder.encode(SecureTokens.generate("timing-"));
    }

    // ------------------------------------------------------------------ registration

    public void register(Registration request, ClientInfo client) {
        String email = normalizeEmail(request.email());
        throttle.consumeMailQuota(AuthThrottle.ipKey(MAIL, client.ip()), AuthThrottle.accountKey(MAIL, email));
        policy.check(request.password(), email, request.displayName());
        if (request.accountType() == AccountType.BUSINESS
                && (request.organizationName() == null || request.organizationName().isBlank())) {
            throw ApiException.badRequest("ORGANIZATION_NAME_REQUIRED", "A business account needs an organization name.");
        }
        // hash first, so that new and existing e-mails cost the same time
        String passwordHash = encoder.encode(request.password());

        Optional<UserRef> existing = lookups.userByEmail(email);
        if (existing.isPresent()) {
            notifyExistingAccount(existing.get(), client);
            return;
        }
        UUID tenantId = UUID.randomUUID();
        try {
            tenantScope.runAs(tenantId, () -> tx.executeWithoutResult(status -> {
                Instant now = clock.instant();
                String locale = normalizeLocale(request.locale());
                String displayName = request.displayName().trim();
                UUID userId;
                if (request.accountType() == AccountType.BUSINESS) {
                    tenants.insertTenant(tenantId, TenantType.BUSINESS, request.organizationName().trim(), now);
                    UUID organizationId = tenants.insertOrganization(tenantId, request.organizationName().trim(), now);
                    userId = users.insert(tenantId, email, passwordHash, displayName, locale, now);
                    assignments.insert(tenantId, userId, "ORGANIZATION_ADMIN", ScopeType.ORGANIZATION, organizationId,
                            null, now);
                } else {
                    tenants.insertTenant(tenantId, TenantType.INDIVIDUAL, displayName, now);
                    userId = users.insert(tenantId, email, passwordHash, displayName, locale, now);
                    assignments.insert(tenantId, userId, "CUSTOMER", ScopeType.TENANT, null, null, now);
                }
                String token = SecureTokens.generate(SecureTokens.EMAIL_TOKEN_PREFIX);
                actionTokens.replace(tenantId, userId, Purpose.EMAIL_VERIFICATION, SecureTokens.sha256(token), now,
                        now.plus(tokenSettings.emailVerificationTtl()));
                mailer.verifyEmail(email, locale, displayName, token);
                audit.record(AuditEvent.of(AuditAction.USER_REGISTERED).tenant(tenantId).user(userId)
                        .target("USER", userId).client(client).detail("accountType", request.accountType().name())
                        .build());
            }));
        } catch (DuplicateKeyException race) {
            // the same e-mail was registered concurrently: behave as for an existing account
            lookups.userByEmail(email).ifPresent(ref -> notifyExistingAccount(ref, client));
        }
    }

    private void notifyExistingAccount(UserRef ref, ClientInfo client) {
        tenantScope.runAs(ref.tenantId(), () -> tx.executeWithoutResult(status -> {
            users.findById(ref.userId()).ifPresent(user -> {
                mailer.accountExists(user.email(), user.locale(), user.displayName());
                audit.record(AuditEvent.of(AuditAction.REGISTRATION_EXISTING_EMAIL).tenant(ref.tenantId())
                        .target("USER", user.id()).client(client).build());
            });
        }));
    }

    // ------------------------------------------------------------------ e-mail verification

    public void verifyEmail(String token, ClientInfo client) {
        byte[] hash = SecureTokens.sha256(token);
        UUID tenantId = lookups.tenantBySecret(SecretKind.USER_ACTION_TOKEN, hash).orElse(null);
        boolean verified = tenantId != null && tenantScope.callAs(tenantId, () -> tx.execute(status -> {
            Instant now = clock.instant();
            Optional<ActionToken> usable = actionTokens.lockUsable(hash, Purpose.EMAIL_VERIFICATION, now);
            usable.ifPresent(t -> {
                actionTokens.markUsed(t.id(), now);
                users.markEmailVerified(t.userId(), now);
                audit.record(AuditEvent.of(AuditAction.EMAIL_VERIFIED).tenant(tenantId).user(t.userId())
                        .target("USER", t.userId()).client(client).build());
            });
            return usable.isPresent();
        }));
        if (!verified) {
            audit.record(AuditEvent.of(AuditAction.EMAIL_VERIFICATION_FAILED).failure("INVALID_TOKEN").client(client)
                    .build());
            throw invalidToken();
        }
    }

    public void resendVerification(String rawEmail, ClientInfo client) {
        String email = normalizeEmail(rawEmail);
        throttle.consumeMailQuota(AuthThrottle.ipKey(MAIL, client.ip()), AuthThrottle.accountKey(MAIL, email));
        lookups.userByEmail(email).ifPresent(ref -> tenantScope.runAs(ref.tenantId(), () -> tx.executeWithoutResult(s -> {
            users.findById(ref.userId())
                    .filter(user -> user.status() == UserRecord.Status.PENDING_VERIFICATION)
                    // invited users without a password complete the invitation instead (M4)
                    .filter(user -> user.passwordHash() != null)
                    .ifPresent(user -> {
                        Instant now = clock.instant();
                        String token = SecureTokens.generate(SecureTokens.EMAIL_TOKEN_PREFIX);
                        actionTokens.replace(ref.tenantId(), user.id(), Purpose.EMAIL_VERIFICATION,
                                SecureTokens.sha256(token), now, now.plus(tokenSettings.emailVerificationTtl()));
                        mailer.verifyEmail(user.email(), user.locale(), user.displayName(), token);
                    });
        })));
    }

    // ------------------------------------------------------------------ login

    public LoginResult login(String rawEmail, String password, String deviceLabel, ClientInfo client) {
        String email = normalizeEmail(rawEmail);
        String accountKey = AuthThrottle.accountKey(LOGIN, email);
        String ipKey = AuthThrottle.ipKey(LOGIN, client.ip());
        try {
            throttle.ensureNotBlocked(accountKey, ipKey);
        } catch (ApiException blocked) {
            audit.record(AuditEvent.of(AuditAction.LOGIN_BLOCKED).failure("THROTTLED").client(client)
                    .detail("emailSha256", SecureTokens.sha256Hex(email)).build());
            throw blocked;
        }

        Optional<UserRef> ref = lookups.userByEmail(email);
        if (ref.isEmpty()) {
            encoder.matches(password, timingHash);
            loginFailed(accountKey, ipKey, null, null, "UNKNOWN_ACCOUNT", email, client);
        }
        UUID tenantId = ref.get().tenantId();
        UserRecord user = tenantScope.callAs(tenantId, () -> tx.execute(s -> users.findById(ref.get().userId())))
                .orElseThrow(AuthenticationService::invalidCredentials);

        if (!verifyPassword(user, password)) {
            loginFailed(accountKey, ipKey, tenantId, user.id(), "BAD_PASSWORD", email, client);
        }
        if (user.status() == UserRecord.Status.DISABLED) {
            loginFailed(accountKey, ipKey, tenantId, user.id(), "ACCOUNT_DISABLED", email, client);
        }
        if (user.status() == UserRecord.Status.PENDING_VERIFICATION) {
            // the password was correct: telling the owner that the e-mail must be confirmed leaks nothing
            tenantScope.runAs(tenantId, () -> audit.record(AuditEvent.of(AuditAction.LOGIN_FAILURE).tenant(tenantId)
                    .user(user.id()).failure("EMAIL_NOT_VERIFIED").client(client).build()));
            throw new ApiException(HttpStatus.FORBIDDEN, "EMAIL_NOT_VERIFIED",
                    "Confirm your e-mail address before signing in.");
        }
        throttle.reset(accountKey);
        return tenantScope.callAs(tenantId, () -> tx.execute(s -> {
            Instant now = clock.instant();
            if (encoder.upgradeEncoding(user.passwordHash())) {
                users.updatePassword(user.id(), encoder.encode(password), now);
            }
            users.recordLogin(user.id(), now);
            IssuedSession session = sessions.open(user, client, sanitizeLabel(deviceLabel));
            audit.record(AuditEvent.of(AuditAction.LOGIN_SUCCESS).tenant(tenantId).user(user.id())
                    .target("SESSION", session.sessionId()).client(client).build());
            return new LoginResult(session, user);
        }));
    }

    /** Primary credential check (password). */
    private boolean verifyPassword(UserRecord user, String password) {
        if (user.passwordHash() == null) {
            encoder.matches(password, timingHash);
            return false;
        }
        return encoder.matches(password, user.passwordHash());
    }

    private void loginFailed(String accountKey, String ipKey, UUID tenantId, UUID userId, String reason, String email,
            ClientInfo client) {
        throttle.accountFailure(accountKey);
        throttle.ipFailure(ipKey);
        AuditEvent.Builder event = AuditEvent.of(AuditAction.LOGIN_FAILURE).failure(reason).client(client);
        if (tenantId == null) {
            event.detail("emailSha256", SecureTokens.sha256Hex(email));
            audit.record(event.build());
        } else {
            tenantScope.runAs(tenantId, () -> audit.record(event.tenant(tenantId).user(userId).build()));
        }
        throw invalidCredentials();
    }

    // ------------------------------------------------------------------ password reset

    public void forgotPassword(String rawEmail, ClientInfo client) {
        String email = normalizeEmail(rawEmail);
        throttle.consumeMailQuota(AuthThrottle.ipKey(MAIL, client.ip()), AuthThrottle.accountKey(MAIL, email));
        lookups.userByEmail(email).ifPresent(ref -> tenantScope.runAs(ref.tenantId(), () -> tx.executeWithoutResult(s -> {
            users.findById(ref.userId())
                    .filter(user -> user.status() != UserRecord.Status.DISABLED)
                    .ifPresent(user -> {
                        Instant now = clock.instant();
                        String token = SecureTokens.generate(SecureTokens.EMAIL_TOKEN_PREFIX);
                        actionTokens.replace(ref.tenantId(), user.id(), Purpose.PASSWORD_RESET,
                                SecureTokens.sha256(token), now, now.plus(tokenSettings.passwordResetTtl()));
                        mailer.resetPassword(user.email(), user.locale(), user.displayName(), token);
                        audit.record(AuditEvent.of(AuditAction.PASSWORD_RESET_REQUESTED).tenant(ref.tenantId())
                                .target("USER", user.id()).client(client).build());
                    });
        })));
    }

    public void resetPassword(String token, String newPassword, ClientInfo client) {
        if (newPassword == null || newPassword.length() > PasswordPolicy.MAX_LENGTH) {
            policy.check(newPassword, null, null);
        }
        byte[] hash = SecureTokens.sha256(token);
        UUID tenantId = lookups.tenantBySecret(SecretKind.USER_ACTION_TOKEN, hash).orElse(null);
        if (tenantId == null) {
            resetFailed(client);
        }
        String newHash = encoder.encode(newPassword);
        boolean done = tenantScope.callAs(tenantId, () -> tx.execute(status -> {
            Instant now = clock.instant();
            Optional<ActionToken> usable = actionTokens.lockUsable(hash, Purpose.PASSWORD_RESET, now);
            if (usable.isEmpty()) {
                return false;
            }
            UserRecord user = users.lockById(usable.get().userId()).orElseThrow();
            if (user.status() == UserRecord.Status.DISABLED) {
                return false;
            }
            // policy needs the e-mail/name: checked inside, before anything is changed
            policy.check(newPassword, user.email(), user.displayName());
            actionTokens.markUsed(usable.get().id(), now);
            users.updatePassword(user.id(), newHash, now);
            // the reset link proves control of the mailbox
            users.markEmailVerified(user.id(), now);
            int revoked = sessionRepository.revokeAllForUser(user.id(), null, RevokeReason.PASSWORD_RESET, now);
            audit.record(AuditEvent.of(AuditAction.PASSWORD_RESET).tenant(tenantId).user(user.id())
                    .target("USER", user.id()).client(client).detail("revokedSessions", revoked).build());
            return true;
        }));
        if (!done) {
            resetFailed(client);
        }
    }

    // ------------------------------------------------------------------ invitations

    /**
     * Completes an invitation: the invited user (created by an administrator without a
     * password) chooses the password. The link proves control of the mailbox, so the e-mail
     * is marked verified and the account becomes active. Works only once, only for users that
     * still have no password and are not disabled.
     */
    public void acceptInvitation(String token, String newPassword, ClientInfo client) {
        if (newPassword == null || newPassword.length() > PasswordPolicy.MAX_LENGTH) {
            policy.check(newPassword, null, null);
        }
        byte[] hash = SecureTokens.sha256(token);
        UUID tenantId = lookups.tenantBySecret(SecretKind.USER_ACTION_TOKEN, hash).orElse(null);
        if (tenantId == null) {
            invitationFailed(client);
        }
        String newHash = encoder.encode(newPassword);
        boolean done = tenantScope.callAs(tenantId, () -> tx.execute(status -> {
            Instant now = clock.instant();
            Optional<ActionToken> usable = actionTokens.lockUsable(hash, Purpose.INVITATION, now);
            if (usable.isEmpty()) {
                return false;
            }
            UserRecord user = users.lockById(usable.get().userId()).orElseThrow();
            if (user.status() == UserRecord.Status.DISABLED || user.passwordHash() != null) {
                return false;
            }
            policy.check(newPassword, user.email(), user.displayName());
            actionTokens.markUsed(usable.get().id(), now);
            users.updatePassword(user.id(), newHash, now);
            users.markEmailVerified(user.id(), now);
            audit.record(AuditEvent.of(AuditAction.INVITATION_ACCEPTED).tenant(tenantId).user(user.id())
                    .target("USER", user.id()).client(client).build());
            return true;
        }));
        if (!done) {
            invitationFailed(client);
        }
    }

    private void invitationFailed(ClientInfo client) {
        audit.record(AuditEvent.of(AuditAction.INVITATION_ACCEPT_FAILED).failure("INVALID_TOKEN").client(client)
                .build());
        throw invalidToken();
    }

    private void resetFailed(ClientInfo client) {
        audit.record(AuditEvent.of(AuditAction.PASSWORD_RESET_FAILED).failure("INVALID_TOKEN").client(client).build());
        throw invalidToken();
    }

    // ------------------------------------------------------------------ helpers

    static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeLocale(String locale) {
        return "en".equalsIgnoreCase(locale) ? "en" : "it";
    }

    private static String sanitizeLabel(String label) {
        if (label == null || label.isBlank()) {
            return null;
        }
        String clean = label.replaceAll("\\p{Cntrl}", "").trim();
        return clean.length() > 100 ? clean.substring(0, 100) : clean;
    }

    private static ApiException invalidCredentials() {
        return ApiException.unauthorized("INVALID_CREDENTIALS", "E-mail or password is not correct.");
    }

    private static ApiException invalidToken() {
        return ApiException.badRequest("INVALID_TOKEN", "The link is not valid or has expired.");
    }
}
