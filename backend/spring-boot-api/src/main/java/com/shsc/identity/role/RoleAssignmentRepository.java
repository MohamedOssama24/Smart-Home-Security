package com.shsc.identity.role;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.identity.access.RoleAssignment;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.persistence.Sql;

/** Role assignments of the current tenant (RLS). */
@Repository
public class RoleAssignmentRepository {

    public record StoredAssignment(RoleAssignment assignment, UUID userId, UUID grantedBy, Instant grantedAt) {
    }

    private final JdbcClient jdbc;

    public RoleAssignmentRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(UUID tenantId, UUID userId, String role, ScopeType scopeType, UUID scopeId, UUID grantedBy,
            Instant now) {
        return jdbc.sql("""
                INSERT INTO user_role_assignments (tenant_id, user_id, role_code, scope_type, scope_id, granted_by, granted_at)
                VALUES (:tenant, :user, :role, :scopeType, :scopeId, :grantedBy, :now) RETURNING id""")
                .param("tenant", tenantId).param("user", userId).param("role", role)
                .param("scopeType", scopeType.name()).param("scopeId", scopeId).param("grantedBy", grantedBy)
                .param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public List<RoleAssignment> forUser(UUID userId) {
        return jdbc.sql("""
                SELECT id, role_code, scope_type, scope_id FROM user_role_assignments
                WHERE user_id = :user ORDER BY granted_at""")
                .param("user", userId).query(RoleAssignmentRepository::mapAssignment).list();
    }

    public List<StoredAssignment> detailedForUser(UUID userId) {
        return jdbc.sql("""
                SELECT id, user_id, role_code, scope_type, scope_id, granted_by, granted_at
                FROM user_role_assignments WHERE user_id = :user ORDER BY granted_at""")
                .param("user", userId).query(RoleAssignmentRepository::mapStored).list();
    }

    public Optional<StoredAssignment> lock(UUID assignmentId) {
        return jdbc.sql("""
                SELECT id, user_id, role_code, scope_type, scope_id, granted_by, granted_at
                FROM user_role_assignments WHERE id = :id FOR UPDATE""")
                .param("id", assignmentId).query(RoleAssignmentRepository::mapStored).optional();
    }

    public void delete(UUID assignmentId) {
        jdbc.sql("DELETE FROM user_role_assignments WHERE id = :id").param("id", assignmentId).update();
    }

    /** Number of distinct enabled users holding {@code role} with a tenant-wide scope. */
    public int countTenantWideHolders(String role) {
        return jdbc.sql("""
                SELECT count(DISTINCT a.user_id) FROM user_role_assignments a JOIN users u ON u.id = a.user_id
                WHERE a.role_code = :role AND a.scope_type NOT IN ('HOME', 'CUSTOMER') AND u.status <> 'DISABLED'""")
                .param("role", role).query(Integer.class).single();
    }

    /** Assignments of every user of the tenant, grouped by user (one query for the user list). */
    public List<StoredAssignment> all() {
        return jdbc.sql("""
                SELECT id, user_id, role_code, scope_type, scope_id, granted_by, granted_at
                FROM user_role_assignments ORDER BY granted_at""")
                .query(RoleAssignmentRepository::mapStored).list();
    }

    private static RoleAssignment mapAssignment(ResultSet rs, int row) throws SQLException {
        return new RoleAssignment(Sql.uuid(rs, "id"), rs.getString("role_code"),
                ScopeType.valueOf(rs.getString("scope_type")), Sql.uuid(rs, "scope_id"));
    }

    private static StoredAssignment mapStored(ResultSet rs, int row) throws SQLException {
        return new StoredAssignment(mapAssignment(rs, row), Sql.uuid(rs, "user_id"), Sql.uuid(rs, "granted_by"),
                Sql.instant(rs, "granted_at"));
    }
}
