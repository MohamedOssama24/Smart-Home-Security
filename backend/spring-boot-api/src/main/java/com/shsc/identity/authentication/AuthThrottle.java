package com.shsc.identity.authentication;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.persistence.Sql;
import com.shsc.shared.web.ApiException;

/**
 * Brute-force and abuse protection stored in PostgreSQL (works with several API instances,
 * no Redis needed). Keys are the hashed e-mail (so an unknown e-mail is throttled exactly
 * like a registered one: no account enumeration) and the client IP.
 * <ul>
 * <li>account: after N failures in the window, temporary lock that doubles at each new
 * lock (1 min, 2, 4 … up to 1 h);</li>
 * <li>IP: after M failures in the window, lock for a fixed time;</li>
 * <li>e-mail sending endpoints: max K requests per window per IP and per account.</li>
 * </ul>
 */
@Component
public class AuthThrottle {

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final ShscProperties.Throttle settings;
    private final Clock clock;

    public AuthThrottle(JdbcClient jdbc, TransactionTemplate tx, ShscProperties properties, Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.settings = properties.security().throttle();
        this.clock = clock;
    }

    public static String accountKey(String scope, String email) {
        return scope + ":acct:" + SecureTokens.sha256Hex(email.trim().toLowerCase(Locale.ROOT));
    }

    public static String ipKey(String scope, String ip) {
        return scope + ":ip:" + ip;
    }

    /** Throws 429 if any of the keys is currently blocked. */
    public void ensureNotBlocked(String... keys) {
        Instant now = clock.instant();
        Duration longest = Duration.ZERO;
        for (String key : keys) {
            Optional<Instant> until = tx.execute(status -> jdbc.sql(
                    "SELECT blocked_until FROM auth_throttle WHERE key = :key AND blocked_until > :now")
                    .param("key", key).param("now", Sql.ts(now))
                    .query((rs, n) -> Sql.instant(rs, "blocked_until")).optional());
            if (until.isPresent()) {
                Duration remaining = Duration.between(now, until.get());
                if (remaining.compareTo(longest) > 0) {
                    longest = remaining;
                }
            }
        }
        if (!longest.isZero()) {
            throw ApiException.tooManyRequests(longest);
        }
    }

    /** Records a failed login for the account key (progressive lock). */
    public void accountFailure(String key) {
        recordFailure(key, settings.accountMaxFailures(), true, settings.accountBaseLock());
    }

    /** Records a failed login for the IP key (fixed lock). */
    public void ipFailure(String key) {
        recordFailure(key, settings.ipMaxFailures(), false, settings.ipLock());
    }

    /** Counts a request against a quota; throws 429 once the quota of the window is exceeded. */
    public void consumeMailQuota(String... keys) {
        for (String key : keys) {
            int count = increment(key);
            if (count > settings.mailRequestsPerWindow()) {
                throw ApiException.tooManyRequests(settings.window());
            }
        }
    }

    public void reset(String key) {
        tx.executeWithoutResult(status -> jdbc.sql("DELETE FROM auth_throttle WHERE key = :key").param("key", key).update());
    }

    private void recordFailure(String key, int maxFailures, boolean progressive, Duration baseLock) {
        int failures = increment(key);
        if (failures < maxFailures) {
            return;
        }
        Instant now = clock.instant();
        tx.executeWithoutResult(status -> {
            int lockouts = jdbc.sql("SELECT lockouts FROM auth_throttle WHERE key = :key FOR UPDATE")
                    .param("key", key).query(Integer.class).single();
            Duration lock = baseLock;
            if (progressive) {
                lock = baseLock.multipliedBy(1L << Math.min(lockouts, 12));
                if (lock.compareTo(settings.accountMaxLock()) > 0) {
                    lock = settings.accountMaxLock();
                }
            }
            jdbc.sql("""
                    UPDATE auth_throttle SET blocked_until = :until, lockouts = lockouts + 1, failures = 0,
                        window_start = :now, updated_at = :now WHERE key = :key""")
                    .param("key", key).param("until", Sql.ts(now.plus(lock))).param("now", Sql.ts(now)).update();
        });
    }

    /** Atomically increments the counter of the current window and returns the new value. */
    private int increment(String key) {
        Instant now = clock.instant();
        Instant windowStart = now.minus(settings.window());
        return tx.execute(status -> jdbc.sql("""
                INSERT INTO auth_throttle (key, failures, window_start, updated_at)
                VALUES (:key, 1, :now, :now)
                ON CONFLICT (key) DO UPDATE SET
                    failures = CASE WHEN auth_throttle.window_start < :windowStart THEN 1
                                    ELSE auth_throttle.failures + 1 END,
                    window_start = CASE WHEN auth_throttle.window_start < :windowStart THEN :now
                                        ELSE auth_throttle.window_start END,
                    updated_at = :now
                RETURNING failures""")
                .param("key", key).param("now", Sql.ts(now)).param("windowStart", Sql.ts(windowStart))
                .query(Integer.class).single());
    }
}
