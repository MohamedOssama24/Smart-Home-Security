package com.shsc.customers;

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

/** Customers of the current (BUSINESS) tenant (RLS). Archived customers are excluded. */
@Repository
public class CustomerRepository {

    public record Customer(UUID id, String displayName, String contactEmail, String contactPhone, String notes,
            Instant createdAt, Instant updatedAt) {
    }

    public record CustomerData(String displayName, String contactEmail, String contactPhone, String notes) {
    }

    private static final String COLUMNS =
            "id, display_name, contact_email, contact_phone, notes, created_at, updated_at";

    private final JdbcClient jdbc;

    public CustomerRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Customer insert(UUID tenantId, CustomerData data, UUID createdBy, Instant now) {
        return jdbc.sql("""
                INSERT INTO customers (tenant_id, display_name, contact_email, contact_phone, notes, created_by,
                    created_at, updated_at)
                VALUES (:tenant, :name, :email, :phone, :notes, :by, :now, :now)
                RETURNING """ + " " + COLUMNS)
                .param("tenant", tenantId).param("name", data.displayName()).param("email", data.contactEmail())
                .param("phone", data.contactPhone()).param("notes", data.notes()).param("by", createdBy)
                .param("now", Sql.ts(now))
                .query(CustomerRepository::map).single();
    }

    public Optional<Customer> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM customers WHERE id = :id AND archived_at IS NULL")
                .param("id", id).query(CustomerRepository::map).optional();
    }

    public Optional<Customer> lock(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM customers WHERE id = :id AND archived_at IS NULL FOR UPDATE")
                .param("id", id).query(CustomerRepository::map).optional();
    }

    public List<Customer> findAll() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM customers WHERE archived_at IS NULL ORDER BY display_name, id")
                .query(CustomerRepository::map).list();
    }

    public List<Customer> findByIds(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        return jdbc.sql("SELECT " + COLUMNS + " " + """
                 FROM customers WHERE archived_at IS NULL AND id IN (:ids) ORDER BY display_name, id""")
                .param("ids", ids).query(CustomerRepository::map).list();
    }

    public Customer update(UUID id, CustomerData data, Instant now) {
        return jdbc.sql("""
                UPDATE customers SET display_name = :name, contact_email = :email, contact_phone = :phone,
                    notes = :notes, updated_at = :now
                WHERE id = :id AND archived_at IS NULL
                RETURNING """ + " " + COLUMNS)
                .param("id", id).param("name", data.displayName()).param("email", data.contactEmail())
                .param("phone", data.contactPhone()).param("notes", data.notes()).param("now", Sql.ts(now))
                .query(CustomerRepository::map).single();
    }

    public void archive(UUID id, Instant now) {
        jdbc.sql("UPDATE customers SET archived_at = :now, updated_at = :now WHERE id = :id AND archived_at IS NULL")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    private static Customer map(ResultSet rs, int row) throws SQLException {
        return new Customer(Sql.uuid(rs, "id"), rs.getString("display_name"), rs.getString("contact_email"),
                rs.getString("contact_phone"), rs.getString("notes"), Sql.instant(rs, "created_at"),
                Sql.instant(rs, "updated_at"));
    }
}
