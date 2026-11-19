package com.shsc.devices;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Device inventory, per-field identifications and category history (RLS: current tenant). */
@Repository
public class DeviceRepository {

    public record Device(UUID id, UUID tenantId, UUID homeId, String mac, boolean macRandomized, UUID probableSameAs,
            String currentIp, List<String> addresses, String hostname, String manufacturer, String model,
            String osName, String detectedCategory, String detectedConfidence, String manualCategory,
            UUID manualCategoryBy, Instant manualCategoryAt, String overallConfidence, String classificationJson,
            String rulesetVersion, Instant firstSeenAt, Instant lastSeenAt, UUID firstScanId, UUID lastScanId) {
    }

    /** Values detected by the fingerprinting of one scan. */
    public record Detected(String currentIp, List<String> addresses, String hostname, String manufacturer,
            String model, String osName, String category, String categoryConfidence, String overallConfidence,
            String classificationJson, String rulesetVersion, Instant seenAt, UUID scanId) {
    }

    public record Identification(String field, String value, String confidence, String sourcesJson, boolean conflict,
            UUID scanId, String rulesetVersion, Instant identifiedAt) {
    }

    public record CategoryChange(String source, String oldCategory, String newCategory, UUID scanId, UUID changedBy,
            Instant changedAt) {
    }

    private static final String COLUMNS = """
            id, tenant_id, home_id, mac::text AS mac, mac_randomized, probable_same_as, host(current_ip) AS current_ip,
            ARRAY(SELECT host(a) FROM unnest(addresses) AS a) AS addresses, hostname, manufacturer, model, os_name,
            detected_category, detected_category_confidence, manual_category, manual_category_by, manual_category_at,
            overall_confidence, classification::text AS classification, ruleset_version, first_seen_at, last_seen_at,
            first_scan_id, last_scan_id""";

    private final JdbcClient jdbc;

    public DeviceRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Device> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE id = :id").param("id", id)
                .query(DeviceRepository::map).optional();
    }

    public Optional<Device> lock(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE id = :id FOR UPDATE").param("id", id)
                .query(DeviceRepository::map).optional();
    }

    /** Identity: (home, MAC) when the MAC is known, otherwise (home, address) among devices without MAC. */
    public Optional<Device> lockIdentity(UUID homeId, String mac, String ip) {
        if (mac != null) {
            return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home AND mac = CAST(:mac AS macaddr) FOR UPDATE")
                    .param("home", homeId).param("mac", mac).query(DeviceRepository::map).optional();
        }
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home AND mac IS NULL AND current_ip = CAST(:ip AS inet) FOR UPDATE")
                .param("home", homeId).param("ip", ip).query(DeviceRepository::map).optional();
    }

    public List<Device> forHome(UUID homeId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home ORDER BY current_ip")
                .param("home", homeId).query(DeviceRepository::map).list();
    }

    /** Another device of the home known under the same name (correlation of randomized MACs). */
    public Optional<UUID> otherWithHostname(UUID homeId, String hostname, UUID exclude) {
        return jdbc.sql("""
                SELECT id FROM devices WHERE home_id = :home AND id <> :exclude AND lower(hostname) = lower(:name)
                ORDER BY last_seen_at DESC LIMIT 1""")
                .param("home", homeId).param("exclude", exclude).param("name", hostname)
                .query(UUID.class).optional();
    }

    public UUID insert(UUID tenantId, UUID homeId, String mac, boolean randomized, Detected d) {
        return jdbc.sql("""
                INSERT INTO devices (tenant_id, home_id, mac, mac_randomized, current_ip, addresses, hostname,
                    manufacturer, model, os_name, detected_category, detected_category_confidence, overall_confidence,
                    classification, ruleset_version, first_seen_at, last_seen_at, first_scan_id, last_scan_id)
                VALUES (:tenant, :home, CAST(:mac AS macaddr), :randomized, CAST(:ip AS inet),
                    CAST(:addresses AS inet[]), :hostname, :manufacturer, :model, :os, :category, :categoryConfidence,
                    :overall, CAST(:classification AS jsonb), :ruleset, :seen, :seen, :scan, :scan)
                RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("mac", mac).param("randomized", randomized)
                .params(detectedParams(d)).query(UUID.class).single();
    }

    public void updateDetected(UUID id, Detected d) {
        jdbc.sql("""
                UPDATE devices SET current_ip = CAST(:ip AS inet), addresses = CAST(:addresses AS inet[]),
                    hostname = :hostname, manufacturer = :manufacturer, model = :model, os_name = :os,
                    detected_category = :category, detected_category_confidence = :categoryConfidence,
                    overall_confidence = :overall, classification = CAST(:classification AS jsonb),
                    ruleset_version = :ruleset, last_seen_at = GREATEST(last_seen_at, :seen), last_scan_id = :scan,
                    version = version + 1
                WHERE id = :id""")
                .param("id", id).params(detectedParams(d)).update();
    }

    public void setProbableSameAs(UUID id, UUID other) {
        jdbc.sql("UPDATE devices SET probable_same_as = :other WHERE id = :id").param("id", id).param("other", other)
                .update();
    }

    public void setManualCategory(UUID id, String category, UUID by, Instant at) {
        jdbc.sql("""
                UPDATE devices SET manual_category = :category, manual_category_by = :by, manual_category_at = :at,
                    version = version + 1
                WHERE id = :id""")
                .param("id", id).param("category", category).param("by", category == null ? null : by)
                .param("at", category == null ? null : Sql.ts(at)).update();
    }

    public void replaceIdentifications(UUID tenantId, UUID deviceId, List<Identification> identifications) {
        jdbc.sql("DELETE FROM device_identifications WHERE device_id = :device").param("device", deviceId).update();
        for (Identification i : identifications) {
            jdbc.sql("""
                    INSERT INTO device_identifications (tenant_id, device_id, scan_id, field, value, confidence, sources,
                        conflict, ruleset_version, identified_at)
                    VALUES (:tenant, :device, :scan, :field, :value, :confidence, CAST(:sources AS jsonb), :conflict,
                        :ruleset, :at)""")
                    .param("tenant", tenantId).param("device", deviceId).param("scan", i.scanId())
                    .param("field", i.field()).param("value", i.value()).param("confidence", i.confidence())
                    .param("sources", i.sourcesJson()).param("conflict", i.conflict())
                    .param("ruleset", i.rulesetVersion()).param("at", Sql.ts(i.identifiedAt())).update();
        }
    }

    public List<Identification> identifications(UUID deviceId) {
        return jdbc.sql("""
                SELECT field, value, confidence, sources::text AS sources, conflict, scan_id, ruleset_version,
                    identified_at
                FROM device_identifications WHERE device_id = :device ORDER BY field""")
                .param("device", deviceId)
                .query((rs, n) -> new Identification(rs.getString("field"), rs.getString("value"),
                        rs.getString("confidence"), rs.getString("sources"), rs.getBoolean("conflict"),
                        Sql.uuid(rs, "scan_id"), rs.getString("ruleset_version"), Sql.instant(rs, "identified_at")))
                .list();
    }

    public void insertCategoryChange(UUID tenantId, UUID deviceId, String source, String oldCategory,
            String newCategory, UUID scanId, UUID changedBy, Instant at) {
        jdbc.sql("""
                INSERT INTO device_category_changes (tenant_id, device_id, source, old_category, new_category, scan_id,
                    changed_by, changed_at)
                VALUES (:tenant, :device, :source, :old, :new, :scan, :by, :at)""")
                .param("tenant", tenantId).param("device", deviceId).param("source", source).param("old", oldCategory)
                .param("new", newCategory).param("scan", scanId).param("by", changedBy).param("at", Sql.ts(at))
                .update();
    }

    public List<CategoryChange> categoryChanges(UUID deviceId) {
        return jdbc.sql("""
                SELECT source, old_category, new_category, scan_id, changed_by, changed_at
                FROM device_category_changes WHERE device_id = :device ORDER BY changed_at DESC, id DESC LIMIT 50""")
                .param("device", deviceId)
                .query((rs, n) -> new CategoryChange(rs.getString("source"), rs.getString("old_category"),
                        rs.getString("new_category"), Sql.uuid(rs, "scan_id"), Sql.uuid(rs, "changed_by"),
                        Sql.instant(rs, "changed_at")))
                .list();
    }

    /** Attributes the observations of the scan at these addresses to the device. */
    public void linkObservations(UUID scanId, List<String> addresses, UUID deviceId) {
        jdbc.sql("""
                UPDATE scan_observations SET device_id = :device
                WHERE scan_id = :scan AND host(ip) = ANY (CAST(:addresses AS text[]))""")
                .param("scan", scanId).param("device", deviceId).param("addresses", textArray(addresses)).update();
    }

    private static java.util.Map<String, Object> detectedParams(Detected d) {
        java.util.Map<String, Object> p = new java.util.HashMap<>();
        p.put("ip", d.currentIp());
        p.put("addresses", textArray(d.addresses()));
        p.put("hostname", d.hostname());
        p.put("manufacturer", d.manufacturer());
        p.put("model", d.model());
        p.put("os", d.osName());
        p.put("category", d.category());
        p.put("categoryConfidence", d.categoryConfidence());
        p.put("overall", d.overallConfidence());
        p.put("classification", d.classificationJson());
        p.put("ruleset", d.rulesetVersion());
        p.put("seen", Sql.ts(d.seenAt()));
        p.put("scan", d.scanId());
        return p;
    }

    /** PostgreSQL array literal of addresses (validated inet values, no quoting needed). */
    private static String textArray(List<String> values) {
        return "{" + String.join(",", values) + "}";
    }

    private static Device map(ResultSet rs, int row) throws SQLException {
        Array addresses = rs.getArray("addresses");
        List<String> list = addresses == null ? List.of() : Arrays.asList((String[]) addresses.getArray());
        return new Device(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "home_id"), rs.getString("mac"),
                rs.getBoolean("mac_randomized"), Sql.uuid(rs, "probable_same_as"), rs.getString("current_ip"), list,
                rs.getString("hostname"), rs.getString("manufacturer"), rs.getString("model"), rs.getString("os_name"),
                rs.getString("detected_category"), rs.getString("detected_category_confidence"),
                rs.getString("manual_category"), Sql.uuid(rs, "manual_category_by"),
                Sql.instant(rs, "manual_category_at"), rs.getString("overall_confidence"),
                rs.getString("classification"), rs.getString("ruleset_version"), Sql.instant(rs, "first_seen_at"),
                Sql.instant(rs, "last_seen_at"), Sql.uuid(rs, "first_scan_id"), Sql.uuid(rs, "last_scan_id"));
    }
}
