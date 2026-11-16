package com.shsc.identity.password;

import java.time.Clock;
import java.time.Instant;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.authentication.AuthThrottle;
import com.shsc.identity.session.SessionRepository;
import com.shsc.identity.session.SessionRepository.RevokeReason;
import com.shsc.identity.user.UserRecord;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * Password change by a signed-in user: requires the current password (throttled, so a stolen
 * access token cannot be used to guess it), applies the policy and revokes every other session.
 */
@Service
public class PasswordChangeService {

    private final UserRepository users;
    private final SessionRepository sessions;
    private final PasswordEncoder encoder;
    private final PasswordPolicy policy;
    private final AuthThrottle throttle;
    private final AuditLog audit;
    private final TransactionTemplate tx;
    private final Clock clock;

    public PasswordChangeService(UserRepository users, SessionRepository sessions, PasswordEncoder encoder,
            PasswordPolicy policy, AuthThrottle throttle, AuditLog audit, TransactionTemplate tx, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.encoder = encoder;
        this.policy = policy;
        this.throttle = throttle;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
    }

    public void change(AuthenticatedUser principal, String currentPassword, String newPassword, ClientInfo client) {
        String key = "pwchange:user:" + principal.userId();
        throttle.ensureNotBlocked(key);
        UserRecord user = tx.execute(s -> users.findById(principal.userId())).orElseThrow(ApiException::notFound);
        if (user.passwordHash() == null || !encoder.matches(currentPassword, user.passwordHash())) {
            throttle.accountFailure(key);
            audit.record(AuditEvent.of(AuditAction.PASSWORD_CHANGE_FAILED).tenant(principal.tenantId())
                    .user(principal.userId()).failure("BAD_CURRENT_PASSWORD").client(client).build());
            throw ApiException.badRequest("INVALID_CURRENT_PASSWORD", "The current password is not correct.");
        }
        policy.check(newPassword, user.email(), user.displayName());
        if (encoder.matches(newPassword, user.passwordHash())) {
            throw ApiException.badRequest("PASSWORD_UNCHANGED", "The new password must differ from the current one.");
        }
        String newHash = encoder.encode(newPassword);
        throttle.reset(key);
        tx.executeWithoutResult(s -> {
            Instant now = clock.instant();
            users.updatePassword(user.id(), newHash, now);
            int revoked = sessions.revokeAllForUser(user.id(), principal.sessionId(), RevokeReason.PASSWORD_CHANGED, now);
            audit.record(AuditEvent.of(AuditAction.PASSWORD_CHANGED).tenant(principal.tenantId()).user(user.id())
                    .target("USER", user.id()).client(client).detail("revokedSessions", revoked).build());
        });
    }
}
