package com.shsc.identity.user;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Users of the current tenant (RLS). Every method must run inside a transaction. */
@Repository
public class UserRepository {

    private static final String COLUMNS = """
            id, tenant_id, email, password_hash, display_name, locale, status, email_verified_at,
            last_login_at, created_at""";

    private final JdbcClient jdbc;

    public UserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(UUID tenantId, String email, String passwordHash, String displayName, String locale,
            Instant now) {
        return jdbc.sql("""
                INSERT INTO users (tenant_id, email, password_hash, display_name, locale, status,
                    password_changed_at, created_at, updated_at)
                VALUES (:tenant, :email, :hash, :name, :locale, 'PENDING_VERIFICATION', :now, :now, :now)
                RETURNING id""")
                .param("tenant", tenantId).param("email", email).param("hash", passwordHash)
                .param("name", displayName).param("locale", locale).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    /** An invited user: no password until the invitation is accepted. */
    public UUID insertInvited(UUID tenantId, String email, String displayName, String locale, Instant now) {
        return jdbc.sql("""
                INSERT INTO users (tenant_id, email, password_hash, display_name, locale, status, created_at, updated_at)
                VALUES (:tenant, :email, NULL, :name, :locale, 'PENDING_VERIFICATION', :now, :now)
                RETURNING id""")
                .param("tenant", tenantId).param("email", email).param("name", displayName).param("locale", locale)
                .param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public void updateDisplayName(UUID id, String displayName, Instant now) {
        jdbc.sql("UPDATE users SET display_name = :name, updated_at = :now WHERE id = :id")
                .param("id", id).param("name", displayName).param("now", Sql.ts(now)).update();
    }

    public void disable(UUID id, Instant now) {
        jdbc.sql("UPDATE users SET status = 'DISABLED', updated_at = :now WHERE id = :id")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    /** Re-enables a disabled user: active if the e-mail was confirmed, otherwise still pending. */
    public void enable(UUID id, Instant now) {
        jdbc.sql("""
                UPDATE users SET status = CASE WHEN email_verified_at IS NULL THEN 'PENDING_VERIFICATION' ELSE 'ACTIVE' END,
                    updated_at = :now
                WHERE id = :id AND status = 'DISABLED'""")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    public Optional<UserRecord> findById(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM users WHERE id = :id").param("id", id)
                .query(UserRepository::map).optional();
    }

    public Optional<UserRecord> lockById(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM users WHERE id = :id FOR UPDATE").param("id", id)
                .query(UserRepository::map).optional();
    }

    public List<UserRecord> findAll() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM users ORDER BY created_at").query(UserRepository::map).list();
    }

    public void markEmailVerified(UUID id, Instant now) {
        jdbc.sql("""
                UPDATE users SET email_verified_at = coalesce(email_verified_at, :now),
                    status = CASE WHEN status = 'PENDING_VERIFICATION' THEN 'ACTIVE' ELSE status END,
                    updated_at = :now
                WHERE id = :id""")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    public void updatePassword(UUID id, String passwordHash, Instant now) {
        jdbc.sql("UPDATE users SET password_hash = :hash, password_changed_at = :now, updated_at = :now WHERE id = :id")
                .param("id", id).param("hash", passwordHash).param("now", Sql.ts(now)).update();
    }

    public void recordLogin(UUID id, Instant now) {
        jdbc.sql("UPDATE users SET last_login_at = :now WHERE id = :id")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    public void updateProfile(UUID id, String displayName, String locale, Instant now) {
        jdbc.sql("UPDATE users SET display_name = :name, locale = :locale, updated_at = :now WHERE id = :id")
                .param("id", id).param("name", displayName).param("locale", locale).param("now", Sql.ts(now))
                .update();
    }

    private static UserRecord map(ResultSet rs, int row) throws SQLException {
        return new UserRecord(
                Sql.uuid(rs, "id"),
                Sql.uuid(rs, "tenant_id"),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getString("display_name"),
                rs.getString("locale"),
                UserRecord.Status.valueOf(rs.getString("status")),
                Sql.instant(rs, "email_verified_at"),
                Sql.instant(rs, "last_login_at"),
                Sql.instant(rs, "created_at"));
    }
}
