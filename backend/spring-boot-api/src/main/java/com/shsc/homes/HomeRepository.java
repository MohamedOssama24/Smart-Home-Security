package com.shsc.homes;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Homes of the current tenant (RLS). Archived homes are excluded everywhere. */
@Repository
public class HomeRepository {

    public record Home(UUID id, String name, UUID customerId, String address, String timezone, UUID createdBy,
            Instant createdAt, Instant updatedAt) {
    }

    public record HomeData(String name, UUID customerId, String address, String timezone) {
    }

    private static final String COLUMNS = "id, name, customer_id, address, timezone, created_by, created_at, updated_at";

    private final JdbcClient jdbc;

    public HomeRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Home insert(UUID tenantId, HomeData data, UUID createdBy, Instant now) {
        return jdbc.sql("""
                INSERT INTO homes (tenant_id, name, customer_id, address, timezone, created_by, created_at, updated_at)
                VALUES (:tenant, :name, :customer, :address, :timezone, :by, :now, :now)
                RETURNING """ + " " + COLUMNS)
                .param("tenant", tenantId).param("name", data.name()).param("customer", data.customerId())
                .param("address", data.address()).param("timezone", data.timezone()).param("by", createdBy)
                .param("now", Sql.ts(now))
                .query(HomeRepository::map).single();
    }

    public Optional<Home> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM homes WHERE id = :id AND archived_at IS NULL")
                .param("id", id).query(HomeRepository::map).optional();
    }

    /** Locks the home row: serializes changes to the home and to its networks. */
    public Optional<Home> lock(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM homes WHERE id = :id AND archived_at IS NULL FOR UPDATE")
                .param("id", id).query(HomeRepository::map).optional();
    }

    /** Customer the home belongs to (B2B), if any. */
    public Optional<UUID> customerOf(UUID homeId) {
        return jdbc.sql("SELECT customer_id FROM homes WHERE id = :id AND archived_at IS NULL")
                .param("id", homeId).query((rs, n) -> Optional.ofNullable(Sql.uuid(rs, "customer_id")))
                .optional().flatMap(c -> c);
    }

    /** All homes of the tenant, optionally only those of one customer. */
    public List<Home> findAll(UUID customerId) {
        return jdbc.sql("SELECT " + COLUMNS + " " + """
                 FROM homes WHERE archived_at IS NULL
                  AND (CAST(:customer AS uuid) IS NULL OR customer_id = :customer)
                ORDER BY created_at""")
                .param("customer", customerId).query(HomeRepository::map).list();
    }

    /** Homes listed explicitly or belonging to one of the customers (scoped users). */
    public List<Home> findVisible(Collection<UUID> homeIds, Collection<UUID> customerIds, UUID customerId) {
        if (homeIds.isEmpty() && customerIds.isEmpty()) {
            return List.of();
        }
        // an empty IN list is not valid SQL: a random id never matches
        Collection<UUID> homes = homeIds.isEmpty() ? List.of(UUID.randomUUID()) : homeIds;
        Collection<UUID> customers = customerIds.isEmpty() ? List.of(UUID.randomUUID()) : customerIds;
        return jdbc.sql("SELECT " + COLUMNS + " " + """
                 FROM homes WHERE archived_at IS NULL
                  AND (id IN (:homes) OR customer_id IN (:customers))
                  AND (CAST(:customer AS uuid) IS NULL OR customer_id = :customer)
                ORDER BY created_at""")
                .param("homes", homes).param("customers", customers).param("customer", customerId)
                .query(HomeRepository::map).list();
    }

    public int countActive() {
        return jdbc.sql("SELECT count(*) FROM homes WHERE archived_at IS NULL").query(Integer.class).single();
    }

    public int countActiveOfCustomer(UUID customerId) {
        return jdbc.sql("SELECT count(*) FROM homes WHERE archived_at IS NULL AND customer_id = :customer")
                .param("customer", customerId).query(Integer.class).single();
    }

    public Home update(UUID id, HomeData data, Instant now) {
        return jdbc.sql("""
                UPDATE homes SET name = :name, customer_id = :customer, address = :address, timezone = :timezone,
                    updated_at = :now
                WHERE id = :id AND archived_at IS NULL
                RETURNING """ + " " + COLUMNS)
                .param("id", id).param("name", data.name()).param("customer", data.customerId())
                .param("address", data.address()).param("timezone", data.timezone()).param("now", Sql.ts(now))
                .query(HomeRepository::map).single();
    }

    public void archive(UUID id, Instant now) {
        jdbc.sql("UPDATE homes SET archived_at = :now, updated_at = :now WHERE id = :id AND archived_at IS NULL")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    private static Home map(ResultSet rs, int row) throws SQLException {
        return new Home(Sql.uuid(rs, "id"), rs.getString("name"), Sql.uuid(rs, "customer_id"),
                rs.getString("address"), rs.getString("timezone"), Sql.uuid(rs, "created_by"),
                Sql.instant(rs, "created_at"), Sql.instant(rs, "updated_at"));
    }
}
