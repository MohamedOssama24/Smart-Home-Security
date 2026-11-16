package com.shsc.identity.authentication;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** One-time e-mail tokens (verification, password reset, invitation); only SHA-256 hashes are stored. */
@Repository
public class ActionTokenRepository {

    public enum Purpose { EMAIL_VERIFICATION, PASSWORD_RESET, INVITATION }

    public record ActionToken(UUID id, UUID userId, Purpose purpose, Instant expiresAt, Instant usedAt) {
    }

    private final JdbcClient jdbc;

    public ActionTokenRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Creates a token, invalidating the still unused ones of the same purpose. */
    public void replace(UUID tenantId, UUID userId, Purpose purpose, byte[] hash, Instant now, Instant expiresAt) {
        jdbc.sql("""
                UPDATE user_action_tokens SET used_at = :now
                WHERE user_id = :user AND purpose = :purpose AND used_at IS NULL""")
                .param("user", userId).param("purpose", purpose.name()).param("now", Sql.ts(now)).update();
        jdbc.sql("""
                INSERT INTO user_action_tokens (tenant_id, user_id, purpose, token_hash, created_at, expires_at)
                VALUES (:tenant, :user, :purpose, :hash, :now, :expires)""")
                .param("tenant", tenantId).param("user", userId).param("purpose", purpose.name())
                .param("hash", hash).param("now", Sql.ts(now)).param("expires", Sql.ts(expiresAt))
                .update();
    }

    /** Locks a token if it is unused, unexpired and of the expected purpose. */
    public Optional<ActionToken> lockUsable(byte[] hash, Purpose purpose, Instant now) {
        return jdbc.sql("""
                SELECT id, user_id, purpose, expires_at, used_at FROM user_action_tokens
                WHERE token_hash = :hash AND purpose = :purpose AND used_at IS NULL AND expires_at > :now
                FOR UPDATE""")
                .param("hash", hash).param("purpose", purpose.name()).param("now", Sql.ts(now))
                .query((rs, n) -> new ActionToken(Sql.uuid(rs, "id"), Sql.uuid(rs, "user_id"),
                        Purpose.valueOf(rs.getString("purpose")), Sql.instant(rs, "expires_at"),
                        Sql.instant(rs, "used_at")))
                .optional();
    }

    /** Invalidates every unused token of the user (e.g. when the user is disabled). */
    public int invalidateAll(UUID userId, Instant now) {
        return jdbc.sql("UPDATE user_action_tokens SET used_at = :now WHERE user_id = :user AND used_at IS NULL")
                .param("user", userId).param("now", Sql.ts(now)).update();
    }

    public void markUsed(UUID tokenId, Instant now) {
        jdbc.sql("UPDATE user_action_tokens SET used_at = :now WHERE id = :id")
                .param("id", tokenId).param("now", Sql.ts(now)).update();
    }
}
