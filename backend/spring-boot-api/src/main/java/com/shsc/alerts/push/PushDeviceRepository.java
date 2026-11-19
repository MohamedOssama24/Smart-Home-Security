package com.shsc.alerts.push;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** FCM registration tokens of the mobile app (tenant-scoped, under RLS). */
@Repository
public class PushDeviceRepository {

    public record PushDevice(UUID id, UUID userId, UUID sessionId, String platform, String token, String locale,
            Instant createdAt, Instant lastSeenAt) {
    }

    private static final String COLUMNS = "id, user_id, session_id, platform, token, locale, created_at, last_seen_at";

    private final JdbcClient jdbc;

    public PushDeviceRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Registers the token, or moves it to this user and session (same installation, new login). */
    public PushDevice upsert(UUID tenantId, UUID userId, UUID sessionId, String platform, String token, String locale,
            Instant now) {
        return jdbc.sql("""
                INSERT INTO push_devices (tenant_id, user_id, session_id, platform, token, locale, created_at,
                    last_seen_at)
                VALUES (:tenant, :user, :session, :platform, :token, :locale, :now, :now)
                ON CONFLICT (tenant_id, token) DO UPDATE SET user_id = EXCLUDED.user_id,
                    session_id = EXCLUDED.session_id, platform = EXCLUDED.platform, locale = EXCLUDED.locale,
                    last_seen_at = EXCLUDED.last_seen_at
                RETURNING\s""" + COLUMNS)
                .param("tenant", tenantId).param("user", userId).param("session", sessionId)
                .param("platform", platform).param("token", token).param("locale", locale).param("now", Sql.ts(now))
                .query((rs, n) -> map(rs)).single();
    }

    public List<PushDevice> ofUser(UUID userId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM push_devices WHERE user_id = :user ORDER BY created_at")
                .param("user", userId).query((rs, n) -> map(rs)).list();
    }

    /** Devices whose login session is still valid: a logout or revocation stops their pushes. */
    public List<PushDevice> activeOfUser(UUID userId, Instant now) {
        return jdbc.sql("""
                SELECT p.id, p.user_id, p.session_id, p.platform, p.token, p.locale, p.created_at, p.last_seen_at
                FROM push_devices p JOIN user_sessions s ON s.id = p.session_id
                WHERE p.user_id = :user AND s.revoked_at IS NULL AND s.expires_at > :now
                ORDER BY p.created_at""")
                .param("user", userId).param("now", Sql.ts(now)).query((rs, n) -> map(rs)).list();
    }

    public boolean hasActive(UUID userId, Instant now) {
        return !activeOfUser(userId, now).isEmpty();
    }

    public Optional<PushDevice> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM push_devices WHERE id = :id")
                .param("id", id).query((rs, n) -> map(rs)).optional();
    }

    public void delete(UUID id) {
        jdbc.sql("DELETE FROM push_devices WHERE id = :id").param("id", id).update();
    }

    private static PushDevice map(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new PushDevice(Sql.uuid(rs, "id"), Sql.uuid(rs, "user_id"), Sql.uuid(rs, "session_id"),
                rs.getString("platform"), rs.getString("token"), rs.getString("locale"),
                Sql.instant(rs, "created_at"), Sql.instant(rs, "last_seen_at"));
    }
}
