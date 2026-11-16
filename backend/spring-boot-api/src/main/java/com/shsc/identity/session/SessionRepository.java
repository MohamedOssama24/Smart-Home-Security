package com.shsc.identity.session;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** User sessions and their refresh tokens (RLS: current tenant only). */
@Repository
public class SessionRepository {

    public enum RevokeReason { LOGOUT, USER_REVOKED, REVOKE_ALL, PASSWORD_CHANGED, PASSWORD_RESET, TOKEN_REUSE, ADMIN }

    public record SessionRow(UUID id, UUID userId, String deviceLabel, String userAgent, String ipAddress,
            Instant createdAt, Instant lastUsedAt, Instant expiresAt, Instant revokedAt) {

        public boolean isActive(Instant now) {
            return revokedAt == null && expiresAt.isAfter(now);
        }
    }

    public record RefreshTokenRow(UUID id, UUID sessionId, Instant expiresAt, Instant usedAt, Instant revokedAt) {
    }

    private static final String SESSION_COLUMNS =
            "id, user_id, device_label, user_agent, ip_address, created_at, last_used_at, expires_at, revoked_at";

    private final JdbcClient jdbc;

    public SessionRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insertSession(UUID tenantId, UUID userId, String deviceLabel, String userAgent, String ip,
            Instant now, Instant expiresAt) {
        return jdbc.sql("""
                INSERT INTO user_sessions (tenant_id, user_id, device_label, user_agent, ip_address,
                    created_at, last_used_at, expires_at)
                VALUES (:tenant, :user, :label, :ua, :ip, :now, :now, :expires) RETURNING id""")
                .param("tenant", tenantId).param("user", userId).param("label", deviceLabel)
                .param("ua", userAgent).param("ip", ip).param("now", Sql.ts(now)).param("expires", Sql.ts(expiresAt))
                .query(UUID.class).single();
    }

    public void insertRefreshToken(UUID tenantId, UUID sessionId, byte[] hash, Instant now, Instant expiresAt) {
        jdbc.sql("""
                INSERT INTO refresh_tokens (tenant_id, session_id, token_hash, created_at, expires_at)
                VALUES (:tenant, :session, :hash, :now, :expires)""")
                .param("tenant", tenantId).param("session", sessionId).param("hash", hash)
                .param("now", Sql.ts(now)).param("expires", Sql.ts(expiresAt))
                .update();
    }

    public Optional<RefreshTokenRow> lockRefreshToken(byte[] hash) {
        return jdbc.sql("""
                SELECT id, session_id, expires_at, used_at, revoked_at FROM refresh_tokens
                WHERE token_hash = :hash FOR UPDATE""")
                .param("hash", hash)
                .query((rs, n) -> new RefreshTokenRow(Sql.uuid(rs, "id"), Sql.uuid(rs, "session_id"),
                        Sql.instant(rs, "expires_at"), Sql.instant(rs, "used_at"), Sql.instant(rs, "revoked_at")))
                .optional();
    }

    public void markRefreshTokenUsed(UUID tokenId, Instant now) {
        jdbc.sql("UPDATE refresh_tokens SET used_at = :now WHERE id = :id")
                .param("id", tokenId).param("now", Sql.ts(now)).update();
    }

    public Optional<SessionRow> lockSession(UUID sessionId) {
        return jdbc.sql("SELECT " + SESSION_COLUMNS + " FROM user_sessions WHERE id = :id FOR UPDATE")
                .param("id", sessionId).query(SessionRepository::map).optional();
    }

    public Optional<SessionRow> findSession(UUID sessionId) {
        return jdbc.sql("SELECT " + SESSION_COLUMNS + " FROM user_sessions WHERE id = :id")
                .param("id", sessionId).query(SessionRepository::map).optional();
    }

    public void touchSession(UUID sessionId, Instant now, String ip, String userAgent) {
        jdbc.sql("UPDATE user_sessions SET last_used_at = :now, ip_address = :ip, user_agent = :ua WHERE id = :id")
                .param("id", sessionId).param("now", Sql.ts(now)).param("ip", ip).param("ua", userAgent).update();
    }

    /** Revokes a session and every refresh token it still has. Returns false if already revoked. */
    public boolean revokeSession(UUID sessionId, RevokeReason reason, Instant now) {
        int updated = jdbc.sql("""
                UPDATE user_sessions SET revoked_at = :now, revoked_reason = :reason
                WHERE id = :id AND revoked_at IS NULL""")
                .param("id", sessionId).param("reason", reason.name()).param("now", Sql.ts(now)).update();
        jdbc.sql("UPDATE refresh_tokens SET revoked_at = :now WHERE session_id = :id AND revoked_at IS NULL")
                .param("id", sessionId).param("now", Sql.ts(now)).update();
        return updated > 0;
    }

    /** Revokes every active session of the user except {@code keep} (nullable). Returns the count. */
    public int revokeAllForUser(UUID userId, UUID keep, RevokeReason reason, Instant now) {
        List<UUID> sessions = jdbc.sql("""
                SELECT id FROM user_sessions WHERE user_id = :user AND revoked_at IS NULL
                    AND (CAST(:keep AS uuid) IS NULL OR id <> CAST(:keep AS uuid))""")
                .param("user", userId).param("keep", keep).query(UUID.class).list();
        sessions.forEach(id -> revokeSession(id, reason, now));
        return sessions.size();
    }

    public List<SessionRow> listActive(UUID userId, Instant now) {
        return jdbc.sql("SELECT " + SESSION_COLUMNS + """
                 FROM user_sessions WHERE user_id = :user AND revoked_at IS NULL AND expires_at > :now
                ORDER BY last_used_at DESC""")
                .param("user", userId).param("now", Sql.ts(now)).query(SessionRepository::map).list();
    }

    private static SessionRow map(ResultSet rs, int row) throws SQLException {
        return new SessionRow(Sql.uuid(rs, "id"), Sql.uuid(rs, "user_id"), rs.getString("device_label"),
                rs.getString("user_agent"), rs.getString("ip_address"), Sql.instant(rs, "created_at"),
                Sql.instant(rs, "last_used_at"), Sql.instant(rs, "expires_at"), Sql.instant(rs, "revoked_at"));
    }
}
