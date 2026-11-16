package com.shsc.networks;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Networks of the homes of the current tenant and their scan authorizations (RLS). */
@Repository
public class NetworkRepository {

    public enum Kind { ETHERNET, WIFI, VLAN, GUEST, UNKNOWN }

    /** Active authorization of a network (attestation by a user), if any. */
    public record Authorization(UUID id, UUID authorizedBy, Instant authorizedAt, String attestationVersion) {
    }

    public record Network(UUID id, UUID homeId, String name, String cidr, int ipVersion, Kind kind, String source,
            Instant createdAt, Instant updatedAt, Authorization authorization) {
    }

    private static final String SELECT = """
            SELECT n.id, n.home_id, n.name, n.cidr::text AS cidr, family(n.cidr) AS ip_version, n.kind, n.source,
                   n.created_at, n.updated_at,
                   a.id AS auth_id, a.authorized_by, a.authorized_at, a.attestation_version
            FROM networks n
            JOIN homes h ON h.id = n.home_id AND h.archived_at IS NULL
            LEFT JOIN network_authorizations a ON a.network_id = n.id AND a.revoked_at IS NULL
            """;

    private final JdbcClient jdbc;

    public NetworkRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(UUID tenantId, UUID homeId, String name, String cidr, Kind kind, UUID createdBy, Instant now) {
        return jdbc.sql("""
                INSERT INTO networks (tenant_id, home_id, name, cidr, kind, created_by, created_at, updated_at)
                VALUES (:tenant, :home, :name, CAST(:cidr AS cidr), :kind, :by, :now, :now) RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("name", name).param("cidr", cidr)
                .param("kind", kind.name()).param("by", createdBy).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public Optional<Network> find(UUID id) {
        return jdbc.sql(SELECT + " WHERE n.id = :id").param("id", id).query(NetworkRepository::map).optional();
    }

    public List<Network> forHome(UUID homeId) {
        return jdbc.sql(SELECT + " WHERE n.home_id = :home ORDER BY n.cidr").param("home", homeId)
                .query(NetworkRepository::map).list();
    }

    /** Networks of the home that overlap the range (contain it or are contained by it). */
    public List<String> overlapping(UUID homeId, String cidr) {
        return jdbc.sql("""
                SELECT cidr::text FROM networks WHERE home_id = :home AND cidr && CAST(:cidr AS cidr) ORDER BY cidr""")
                .param("home", homeId).param("cidr", cidr).query(String.class).list();
    }

    public void update(UUID id, String name, Kind kind, Instant now) {
        jdbc.sql("UPDATE networks SET name = :name, kind = :kind, updated_at = :now WHERE id = :id")
                .param("id", id).param("name", name).param("kind", kind.name()).param("now", Sql.ts(now)).update();
    }

    /** Deletes the network and (cascade) its authorization history; the audit log keeps the events. */
    public void delete(UUID id) {
        jdbc.sql("DELETE FROM networks WHERE id = :id").param("id", id).update();
    }

    public void authorize(UUID tenantId, UUID networkId, UUID userId, String attestationVersion, Instant now) {
        jdbc.sql("""
                INSERT INTO network_authorizations (tenant_id, network_id, authorized_by, authorized_at, attestation_version)
                VALUES (:tenant, :network, :user, :now, :version)""")
                .param("tenant", tenantId).param("network", networkId).param("user", userId)
                .param("now", Sql.ts(now)).param("version", attestationVersion).update();
    }

    /** Revokes the active authorization; returns false if there was none. */
    public boolean revokeAuthorization(UUID networkId, UUID userId, Instant now) {
        return jdbc.sql("""
                UPDATE network_authorizations SET revoked_at = :now, revoked_by = :user
                WHERE network_id = :network AND revoked_at IS NULL""")
                .param("network", networkId).param("user", userId).param("now", Sql.ts(now)).update() > 0;
    }

    private static Network map(ResultSet rs, int row) throws SQLException {
        UUID authId = Sql.uuid(rs, "auth_id");
        Authorization authorization = authId == null ? null : new Authorization(authId, Sql.uuid(rs, "authorized_by"),
                Sql.instant(rs, "authorized_at"), rs.getString("attestation_version"));
        return new Network(Sql.uuid(rs, "id"), Sql.uuid(rs, "home_id"), rs.getString("name"), rs.getString("cidr"),
                rs.getInt("ip_version"), Kind.valueOf(rs.getString("kind")), rs.getString("source"),
                Sql.instant(rs, "created_at"), Sql.instant(rs, "updated_at"), authorization);
    }
}
