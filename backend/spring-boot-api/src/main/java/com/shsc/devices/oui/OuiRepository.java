package com.shsc.devices.oui;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.devices.oui.OuiRegistryParser.Entry;
import com.shsc.shared.persistence.Sql;

/** IEEE registries (public reference data, no tenant). */
@Repository
public class OuiRepository {

    public record RegistryStatus(String registry, int entries, Instant updatedAt) {
    }

    private final JdbcClient jdbc;
    private final NamedParameterJdbcTemplate named;

    public OuiRepository(JdbcClient jdbc, NamedParameterJdbcTemplate named) {
        this.jdbc = jdbc;
        this.named = named;
    }

    /** Replaces the whole content of one registry. */
    public void replace(String registry, List<Entry> entries, Instant now) {
        jdbc.sql("DELETE FROM oui_entries WHERE registry = :registry").param("registry", registry).update();
        MapSqlParameterSource[] rows = entries.stream()
                .map(e -> new MapSqlParameterSource().addValue("prefix", e.prefix())
                        .addValue("length", e.prefixLength()).addValue("organization", e.organization())
                        .addValue("registry", e.registry()).addValue("now", Sql.ts(now)))
                .toArray(MapSqlParameterSource[]::new);
        // the same prefix listed twice in a file: the last one wins
        named.batchUpdate("""
                INSERT INTO oui_entries (prefix, prefix_length, organization, registry, updated_at)
                VALUES (:prefix, :length, :organization, :registry, :now)
                ON CONFLICT (prefix) DO UPDATE SET organization = EXCLUDED.organization,
                    registry = EXCLUDED.registry, prefix_length = EXCLUDED.prefix_length,
                    updated_at = EXCLUDED.updated_at""", rows);
    }

    /** Organization of the longest registered prefix of a MAC address (MA-S, then MA-M, then MA-L). */
    public Optional<String> organizationOf(String mac) {
        String hex = mac.replaceAll("[^0-9A-Fa-f]", "").toUpperCase(Locale.ROOT);
        if (hex.length() != 12) {
            return Optional.empty();
        }
        return jdbc.sql("""
                SELECT organization FROM oui_entries WHERE prefix IN (:p36, :p28, :p24)
                ORDER BY prefix_length DESC LIMIT 1""")
                .param("p36", hex.substring(0, 9)).param("p28", hex.substring(0, 7)).param("p24", hex.substring(0, 6))
                .query(String.class).optional();
    }

    public List<RegistryStatus> status() {
        return jdbc.sql("""
                SELECT registry, count(*) AS entries, max(updated_at) AS updated_at FROM oui_entries
                GROUP BY registry ORDER BY registry""")
                .query((rs, n) -> new RegistryStatus(rs.getString("registry"), rs.getInt("entries"),
                        Sql.instant(rs, "updated_at")))
                .list();
    }
}
