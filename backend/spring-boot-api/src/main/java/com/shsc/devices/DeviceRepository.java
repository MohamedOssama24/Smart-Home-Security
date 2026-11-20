package com.shsc.devices;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.RowCallbackHandler;
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
            String rulesetVersion, Instant firstSeenAt, Instant lastSeenAt, UUID firstScanId, UUID lastScanId,
            String customName) {
    }

    /** Values detected by the fingerprinting of one scan. */
    public record Detected(String currentIp, List<String> addresses, String hostname, String manufacturer,
            String model, String osName, String category, String categoryConfidence, String overallConfidence,
            String classificationJson, String rulesetVersion, Instant seenAt, UUID scanId) {
    }

    public record Identification(String field, String value, String confidence, String sourcesJson, boolean conflict,
            UUID scanId, String rulesetVersion, Instant identifiedAt, String status) {
    }

    /** A change of value or status of an identity field (M20). */
    public record IdentificationChange(String field, String oldValue, String newValue, String oldStatus,
            String newStatus, String origin, UUID scanId, UUID changedBy, Instant changedAt) {
    }

    /** Fields whose changes are kept in the identification history (addresses: M19 history). */
    static final java.util.Set<String> HISTORY_FIELDS = java.util.Set.of("MANUFACTURER", "MODEL", "PRODUCT_CODE",
            "FIRMWARE", "CPE", "OS", "DEVICE_TYPE", "HOSTNAME");
    static final int MAX_HISTORY_PER_FIELD = 50;

    public record CategoryChange(String source, String oldCategory, String newCategory, UUID scanId, UUID changedBy,
            Instant changedAt) {
    }

    private static final String COLUMNS = """
            id, tenant_id, home_id, mac::text AS mac, mac_randomized, probable_same_as, host(current_ip) AS current_ip,
            ARRAY(SELECT host(a) FROM unnest(addresses) AS a) AS addresses, hostname, manufacturer, model, os_name,
            detected_category, detected_category_confidence, manual_category, manual_category_by, manual_category_at,
            overall_confidence, classification::text AS classification, ruleset_version, first_seen_at, last_seen_at,
            first_scan_id, last_scan_id, custom_name""";

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

    /** One MAC address (network interface) of a device (M19). */
    public record Interface(UUID id, String mac, boolean macRandomized, String vendor, String agentInterface,
            Instant firstSeenAt, Instant lastSeenAt, UUID lastScanId) {
    }

    /** One IPv4/IPv6 address in the history of a device (M19). */
    public record Address(UUID id, String address, String mac, Instant firstSeenAt, Instant lastSeenAt,
            UUID firstScanId, UUID lastScanId, int timesSeen) {
    }

    /**
     * Identity: the device owning the MAC among the interfaces of the home (M19), otherwise
     * (home, MAC) of the M8 inventory; without MAC, (home, address) among devices without MAC.
     */
    public Optional<Device> lockIdentity(UUID homeId, String mac, String ip) {
        if (mac != null) {
            Optional<Device> byInterface = jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE id = "
                    + "(SELECT device_id FROM device_interfaces WHERE home_id = :home AND mac = CAST(:mac AS macaddr))"
                    + " FOR UPDATE")
                    .param("home", homeId).param("mac", mac).query(DeviceRepository::map).optional();
            if (byInterface.isPresent()) {
                return byInterface;
            }
            return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home AND mac = CAST(:mac AS macaddr) FOR UPDATE")
                    .param("home", homeId).param("mac", mac).query(DeviceRepository::map).optional();
        }
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home AND mac IS NULL AND current_ip = CAST(:ip AS inet) FOR UPDATE")
                .param("home", homeId).param("ip", ip).query(DeviceRepository::map).optional();
    }

    /** MAC of the device with a MAC currently at each address of the home (most recently seen wins). */
    public java.util.Map<String, String> macByCurrentAddress(UUID homeId) {
        java.util.Map<String, String> out = new java.util.HashMap<>();
        jdbc.sql("""
                SELECT host(current_ip) AS ip, mac::text AS mac FROM devices
                WHERE home_id = :home AND mac IS NOT NULL ORDER BY last_seen_at""")
                .param("home", homeId)
                .query((RowCallbackHandler) rs -> out.put(rs.getString("ip"), rs.getString("mac")));
        return out;
    }

    /**
     * Devices known only by address (seen without MAC, e.g. answering ping only) whose address is
     * the current address of a device with a MAC: {source, target} pairs, the target being the
     * most recently seen such device. A device with something set by the user (manual category,
     * name, confirmed value) is left to the user's own merge.
     */
    public List<UUID[]> addressOnlyTwins(UUID homeId) {
        return jdbc.sql("""
                SELECT o.id AS source,
                    (SELECT t.id FROM devices t WHERE t.home_id = o.home_id AND t.mac IS NOT NULL
                       AND t.current_ip = o.current_ip ORDER BY t.last_seen_at DESC, t.id LIMIT 1) AS target
                FROM devices o
                WHERE o.home_id = :home AND o.mac IS NULL AND o.manual_category IS NULL AND o.custom_name IS NULL
                  AND NOT EXISTS (SELECT 1 FROM device_identity_confirmations c WHERE c.device_id = o.id)
                  AND EXISTS (SELECT 1 FROM devices t WHERE t.home_id = o.home_id AND t.mac IS NOT NULL
                       AND t.current_ip = o.current_ip)
                ORDER BY o.id""")
                .param("home", homeId)
                .query((rs, n) -> new UUID[] {Sql.uuid(rs, "source"), Sql.uuid(rs, "target")}).list();
    }

    /**
     * Devices of the home not seen in {@code scanId} whose stored result is out of date: classified
     * with another ruleset, or a maker MAC still without manufacturer (registry imported since).
     */
    public List<Device> outdated(UUID homeId, UUID scanId, String ruleset, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + """
                 FROM devices
                WHERE home_id = :home AND last_scan_id IS NOT NULL AND last_scan_id <> :scan
                  AND (ruleset_version IS DISTINCT FROM :ruleset
                       OR (mac IS NOT NULL AND NOT mac_randomized AND manufacturer IS NULL))
                ORDER BY last_seen_at DESC LIMIT :limit""")
                .param("home", homeId).param("scan", scanId).param("ruleset", ruleset).param("limit", limit)
                .query(DeviceRepository::map).list();
    }

    public List<Device> forHome(UUID homeId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM devices WHERE home_id = :home ORDER BY current_ip")
                .param("home", homeId).query(DeviceRepository::map).list();
    }

    /**
     * Another device of the home known under the same name ("probably the same device": second
     * interface or privacy MAC), skipping the pairs the user said are different devices.
     */
    public Optional<UUID> otherWithHostname(UUID homeId, String hostname, UUID exclude) {
        return jdbc.sql("""
                SELECT o.id FROM devices o, devices me
                WHERE me.id = :exclude AND o.home_id = :home AND o.id <> me.id AND lower(o.hostname) = lower(:name)
                  AND NOT (o.id = ANY (me.same_as_dismissed)) AND NOT (me.id = ANY (o.same_as_dismissed))
                  AND (o.first_seen_at, o.id) < (me.first_seen_at, me.id)
                ORDER BY o.first_seen_at, o.id LIMIT 1""")
                .param("home", homeId).param("exclude", exclude).param("name", hostname)
                .query(UUID.class).optional();
    }

    /** The user said the two devices are different: no more "probably the same device" between them. */
    public void dismissSameAs(UUID id, UUID other) {
        jdbc.sql("""
                UPDATE devices SET probable_same_as = NULL,
                    same_as_dismissed = CASE
                        WHEN :other = ANY (same_as_dismissed) OR cardinality(same_as_dismissed) >= 64
                            THEN same_as_dismissed
                        ELSE same_as_dismissed || CAST(:other AS uuid) END,
                    version = version + 1
                WHERE id = :id""")
                .param("id", id).param("other", other).update();
    }

    /** Device owning each interface MAC known in the home (grouping of the observations of a scan). */
    public java.util.Map<String, UUID> interfaceOwners(UUID homeId) {
        java.util.Map<String, UUID> owners = new java.util.HashMap<>();
        jdbc.sql("SELECT mac::text AS mac, device_id FROM device_interfaces WHERE home_id = :home")
                .param("home", homeId)
                .query((RowCallbackHandler) rs -> owners.put(rs.getString("mac"), Sql.uuid(rs, "device_id")));
        return owners;
    }

    public void upsertInterface(UUID tenantId, UUID homeId, UUID deviceId, String mac, boolean randomized,
            String vendor, String agentInterface, Instant seenAt, UUID scanId) {
        jdbc.sql("""
                INSERT INTO device_interfaces (tenant_id, home_id, device_id, mac, mac_randomized, vendor,
                    agent_interface, first_seen_at, last_seen_at, first_scan_id, last_scan_id)
                VALUES (:tenant, :home, :device, CAST(:mac AS macaddr), :randomized, :vendor, :iface, :seen, :seen,
                    :scan, :scan)
                ON CONFLICT (home_id, mac) DO UPDATE SET
                    vendor = COALESCE(EXCLUDED.vendor, device_interfaces.vendor),
                    agent_interface = COALESCE(EXCLUDED.agent_interface, device_interfaces.agent_interface),
                    last_seen_at = GREATEST(device_interfaces.last_seen_at, EXCLUDED.last_seen_at),
                    last_scan_id = EXCLUDED.last_scan_id""")
                .param("tenant", tenantId).param("home", homeId).param("device", deviceId).param("mac", mac)
                .param("randomized", randomized).param("vendor", vendor).param("iface", agentInterface)
                .param("seen", Sql.ts(seenAt)).param("scan", scanId).update();
    }

    public void upsertAddress(UUID tenantId, UUID deviceId, String address, String mac, Instant seenAt, UUID scanId) {
        jdbc.sql("""
                INSERT INTO device_addresses (tenant_id, device_id, address, mac, first_seen_at, last_seen_at,
                    first_scan_id, last_scan_id)
                VALUES (:tenant, :device, CAST(:address AS inet), CAST(:mac AS macaddr), :seen, :seen, :scan, :scan)
                ON CONFLICT (device_id, address) DO UPDATE SET
                    mac = COALESCE(EXCLUDED.mac, device_addresses.mac),
                    last_seen_at = GREATEST(device_addresses.last_seen_at, EXCLUDED.last_seen_at),
                    times_seen = device_addresses.times_seen
                        + CASE WHEN device_addresses.last_scan_id IS DISTINCT FROM EXCLUDED.last_scan_id THEN 1 ELSE 0 END,
                    last_scan_id = EXCLUDED.last_scan_id""")
                .param("tenant", tenantId).param("device", deviceId).param("address", address).param("mac", mac)
                .param("seen", Sql.ts(seenAt)).param("scan", scanId).update();
    }

    public List<Interface> interfaces(UUID deviceId) {
        return jdbc.sql("""
                SELECT id, mac::text AS mac, mac_randomized, vendor, agent_interface, first_seen_at, last_seen_at,
                    last_scan_id
                FROM device_interfaces WHERE device_id = :device ORDER BY first_seen_at, mac""")
                .param("device", deviceId)
                .query((rs, n) -> new Interface(Sql.uuid(rs, "id"), rs.getString("mac"),
                        rs.getBoolean("mac_randomized"), rs.getString("vendor"), rs.getString("agent_interface"),
                        Sql.instant(rs, "first_seen_at"), Sql.instant(rs, "last_seen_at"),
                        Sql.uuid(rs, "last_scan_id")))
                .list();
    }

    /** Address history, most recently seen first. */
    public List<Address> addresses(UUID deviceId) {
        return jdbc.sql("""
                SELECT id, host(address) AS address, mac::text AS mac, first_seen_at, last_seen_at, first_scan_id,
                    last_scan_id, times_seen
                FROM device_addresses WHERE device_id = :device
                ORDER BY last_seen_at DESC, family(address), address""")
                .param("device", deviceId)
                .query((rs, n) -> new Address(Sql.uuid(rs, "id"), rs.getString("address"), rs.getString("mac"),
                        Sql.instant(rs, "first_seen_at"), Sql.instant(rs, "last_seen_at"),
                        Sql.uuid(rs, "first_scan_id"), Sql.uuid(rs, "last_scan_id"), rs.getInt("times_seen")))
                .list();
    }

    public void deleteAddresses(List<UUID> ids) {
        if (!ids.isEmpty()) {
            jdbc.sql("DELETE FROM device_addresses WHERE id IN (:ids)").param("ids", ids).update();
        }
    }

    /**
     * Moves everything of {@code source} that belongs to the physical device onto {@code target}
     * (interfaces, address history, observations, ports, alerts, findings not already present on
     * the target with their CVE links) and deletes {@code source}: what is left (identifications,
     * category history, protocols, duplicate findings) is recomputed by the next scan.
     */
    public void merge(UUID source, UUID target) {
        jdbc.sql("UPDATE device_interfaces SET device_id = :target WHERE device_id = :source")
                .param("source", source).param("target", target).update();
        jdbc.sql("""
                INSERT INTO device_addresses (tenant_id, device_id, address, mac, first_seen_at, last_seen_at,
                    first_scan_id, last_scan_id, times_seen)
                SELECT tenant_id, :target, address, mac, first_seen_at, last_seen_at, first_scan_id, last_scan_id,
                    times_seen
                FROM device_addresses WHERE device_id = :source
                ON CONFLICT (device_id, address) DO UPDATE SET
                    mac = COALESCE(device_addresses.mac, EXCLUDED.mac),
                    first_seen_at = LEAST(device_addresses.first_seen_at, EXCLUDED.first_seen_at),
                    last_seen_at = GREATEST(device_addresses.last_seen_at, EXCLUDED.last_seen_at),
                    times_seen = device_addresses.times_seen + EXCLUDED.times_seen""")
                .param("source", source).param("target", target).update();
        for (String table : List.of("scan_observations", "open_ports", "alerts")) {
            jdbc.sql("UPDATE " + table + " SET device_id = :target WHERE device_id = :source")
                    .param("source", source).param("target", target).update();
        }
        jdbc.sql("""
                UPDATE findings SET device_id = :target
                WHERE device_id = :source
                  AND fingerprint NOT IN (SELECT fingerprint FROM findings WHERE device_id = :target)""")
                .param("source", source).param("target", target).update();
        jdbc.sql("""
                UPDATE device_vulnerabilities dv SET device_id = :target
                FROM findings f WHERE dv.finding_id = f.id AND f.device_id = :target AND dv.device_id = :source""")
                .param("source", source).param("target", target).update();
        jdbc.sql("""
                UPDATE devices t SET first_seen_at = LEAST(t.first_seen_at, s.first_seen_at),
                    probable_same_as = NULL, version = t.version + 1
                FROM devices s WHERE t.id = :target AND s.id = :source""")
                .param("source", source).param("target", target).update();
        jdbc.sql("""
                UPDATE device_images SET device_id = :target
                WHERE device_id = :source
                  AND source NOT IN (SELECT source FROM device_images WHERE device_id = :target)""")
                .param("source", source).param("target", target).update(); // M23: keep the photo
        jdbc.sql("""
                UPDATE device_person_assignments SET device_id = :target
                WHERE device_id = :source
                  AND person_id NOT IN (SELECT person_id FROM device_person_assignments WHERE device_id = :target)""")
                .param("source", source).param("target", target).update(); // M24: keep the people
        jdbc.sql("DELETE FROM devices WHERE id = :source").param("source", source).update();
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

    /**
     * Replaces the identifications of a device; every change of value or status of a
     * {@link #HISTORY_FIELDS history field} is recorded (M20), {@code changedBy} null for a scan.
     */
    public void replaceIdentifications(UUID tenantId, UUID deviceId, List<Identification> identifications,
            UUID changedBy, Instant now) {
        java.util.Map<String, Identification> old = new java.util.HashMap<>();
        identifications(deviceId).forEach(i -> old.put(i.field(), i));
        jdbc.sql("DELETE FROM device_identifications WHERE device_id = :device").param("device", deviceId).update();
        java.util.Set<String> fields = new java.util.HashSet<>(old.keySet());
        for (Identification i : identifications) {
            fields.add(i.field());
            jdbc.sql("""
                    INSERT INTO device_identifications (tenant_id, device_id, scan_id, field, value, confidence, sources,
                        conflict, ruleset_version, identified_at, status)
                    VALUES (:tenant, :device, :scan, :field, :value, :confidence, CAST(:sources AS jsonb), :conflict,
                        :ruleset, :at, :status)""")
                    .param("tenant", tenantId).param("device", deviceId).param("scan", i.scanId())
                    .param("field", i.field()).param("value", i.value()).param("confidence", i.confidence())
                    .param("sources", i.sourcesJson()).param("conflict", i.conflict())
                    .param("ruleset", i.rulesetVersion()).param("at", Sql.ts(i.identifiedAt()))
                    .param("status", i.status()).update();
        }
        java.util.Map<String, Identification> current = new java.util.HashMap<>();
        identifications.forEach(i -> current.put(i.field(), i));
        UUID scanId = identifications.stream().map(Identification::scanId).filter(s -> s != null).findFirst()
                .orElse(null);
        for (String field : fields) {
            Identification before = old.get(field);
            Identification after = current.get(field);
            String oldValue = before == null ? null : before.value();
            String newValue = after == null ? null : after.value();
            String oldStatus = before == null ? null : before.status();
            String newStatus = after == null ? null : after.status();
            if (HISTORY_FIELDS.contains(field)
                    && (!java.util.Objects.equals(oldValue, newValue) || !java.util.Objects.equals(oldStatus, newStatus))) {
                insertHistory(tenantId, deviceId, new IdentificationChange(field, oldValue, newValue, oldStatus,
                        newStatus, changedBy == null ? "SCAN" : "USER", changedBy == null ? scanId : null, changedBy,
                        now));
            }
        }
    }

    private void insertHistory(UUID tenantId, UUID deviceId, IdentificationChange c) {
        jdbc.sql("""
                INSERT INTO device_identification_history (tenant_id, device_id, field, old_value, new_value,
                    old_status, new_status, origin, scan_id, changed_by, changed_at)
                VALUES (:tenant, :device, :field, :oldValue, :newValue, :oldStatus, :newStatus, :origin, :scan, :by,
                    :at)""")
                .param("tenant", tenantId).param("device", deviceId).param("field", c.field())
                .param("oldValue", c.oldValue()).param("newValue", c.newValue()).param("oldStatus", c.oldStatus())
                .param("newStatus", c.newStatus()).param("origin", c.origin()).param("scan", c.scanId())
                .param("by", c.changedBy()).param("at", Sql.ts(c.changedAt())).update();
        // bounded history: the last MAX_HISTORY_PER_FIELD changes of each field
        jdbc.sql("""
                DELETE FROM device_identification_history WHERE id IN (
                    SELECT id FROM device_identification_history WHERE device_id = :device AND field = :field
                    ORDER BY changed_at DESC, id DESC OFFSET :max)""")
                .param("device", deviceId).param("field", c.field()).param("max", MAX_HISTORY_PER_FIELD).update();
    }

    public List<IdentificationChange> identificationHistory(UUID deviceId) {
        return jdbc.sql("""
                SELECT field, old_value, new_value, old_status, new_status, origin, scan_id, changed_by, changed_at
                FROM device_identification_history WHERE device_id = :device
                ORDER BY changed_at DESC, id DESC LIMIT 200""")
                .param("device", deviceId)
                .query((rs, n) -> new IdentificationChange(rs.getString("field"), rs.getString("old_value"),
                        rs.getString("new_value"), rs.getString("old_status"), rs.getString("new_status"),
                        rs.getString("origin"), Sql.uuid(rs, "scan_id"), Sql.uuid(rs, "changed_by"),
                        Sql.instant(rs, "changed_at")))
                .list();
    }

    /** Values confirmed by the user, by field (M20). */
    public java.util.Map<String, String> confirmations(UUID deviceId) {
        java.util.Map<String, String> out = new java.util.HashMap<>();
        jdbc.sql("SELECT field, value FROM device_identity_confirmations WHERE device_id = :device")
                .param("device", deviceId)
                .query((RowCallbackHandler) rs -> out.put(rs.getString("field"), rs.getString("value")));
        return out;
    }

    /** Sets (value) or removes (null) the user's confirmation of a field. */
    public void setConfirmation(UUID tenantId, UUID deviceId, String field, String value, UUID by, Instant at) {
        if (value == null) {
            jdbc.sql("DELETE FROM device_identity_confirmations WHERE device_id = :device AND field = :field")
                    .param("device", deviceId).param("field", field).update();
            return;
        }
        jdbc.sql("""
                INSERT INTO device_identity_confirmations (tenant_id, device_id, field, value, confirmed_by, confirmed_at)
                VALUES (:tenant, :device, :field, :value, :by, :at)
                ON CONFLICT (device_id, field) DO UPDATE
                    SET value = EXCLUDED.value, confirmed_by = EXCLUDED.confirmed_by, confirmed_at = EXCLUDED.confirmed_at""")
                .param("tenant", tenantId).param("device", deviceId).param("field", field).param("value", value)
                .param("by", by).param("at", Sql.ts(at)).update();
    }

    /** Name given by the user (M20); never written by a scan. */
    public void setCustomName(UUID id, String name) {
        jdbc.sql("UPDATE devices SET custom_name = :name, version = version + 1 WHERE id = :id").param("id", id)
                .param("name", name).update();
    }

    /** Updates the columns shown in the lists with the values confirmed by the user. */
    public void applyConfirmedColumns(UUID id, String manufacturer, String model, String osName) {
        jdbc.sql("""
                UPDATE devices SET manufacturer = COALESCE(:manufacturer, manufacturer), model = COALESCE(:model, model),
                    os_name = COALESCE(:os, os_name)
                WHERE id = :id""")
                .param("id", id).param("manufacturer", manufacturer).param("model", model).param("os", osName).update();
    }

    public List<Identification> identifications(UUID deviceId) {
        return jdbc.sql("""
                SELECT field, value, confidence, sources::text AS sources, conflict, scan_id, ruleset_version,
                    identified_at, status
                FROM device_identifications WHERE device_id = :device ORDER BY field""")
                .param("device", deviceId)
                .query((rs, n) -> new Identification(rs.getString("field"), rs.getString("value"),
                        rs.getString("confidence"), rs.getString("sources"), rs.getBoolean("conflict"),
                        Sql.uuid(rs, "scan_id"), rs.getString("ruleset_version"), Sql.instant(rs, "identified_at"),
                        rs.getString("status")))
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
                Sql.instant(rs, "last_seen_at"), Sql.uuid(rs, "first_scan_id"), Sql.uuid(rs, "last_scan_id"),
                rs.getString("custom_name"));
    }
}
