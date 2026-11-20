package com.shsc.people;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** People of a home and their devices (M24, ADR-081). RLS: current tenant. */
@Repository
public class PeopleRepository {

    public record Person(UUID id, UUID tenantId, UUID homeId, String name, UUID userId, String origin,
            String externalKey, boolean dismissed, Instant createdAt) {
    }

    /** A non-rejected association of a person with a device. */
    public record Assignment(UUID personId, UUID deviceId, String status, String source, String evidence,
            Instant updatedAt) {
    }

    /** A name announced by a device, with where it comes from (HOSTNAME sources, user's name, Home Assistant). */
    /** Account seen on an address of the home, reported by the agent (M24, ADR-083). */
    public record ScanIdentity(String ip, String account, String source, Instant observedAt) {
    }

    /** An identity of a scan matched to the device that had its address in that scan. */
    public record DeviceIdentity(UUID deviceId, UUID tenantId, String ip, String account, String source,
            Instant observedAt) {
    }

    public record DeviceName(UUID deviceId, UUID tenantId, String mac, String name) {
    }

    private static final String COLUMNS = """
            id, tenant_id, home_id, display_name, user_id, origin, external_key, dismissed, created_at""";

    private final JdbcClient jdbc;

    public PeopleRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    private static Person person(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new Person(rs.getObject("id", UUID.class), rs.getObject("tenant_id", UUID.class),
                rs.getObject("home_id", UUID.class), rs.getString("display_name"), rs.getObject("user_id", UUID.class),
                rs.getString("origin"), rs.getString("external_key"), rs.getBoolean("dismissed"),
                Sql.instant(rs, "created_at"));
    }

    /** Visible people of the home (not dismissed), by name. */
    public List<Person> ofHome(UUID homeId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM home_people WHERE home_id = :home AND NOT dismissed "
                + "ORDER BY lower(display_name)")
                .param("home", homeId).query((rs, n) -> person(rs)).list();
    }

    public Optional<Person> lock(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM home_people WHERE id = :id FOR UPDATE").param("id", id)
                .query((rs, n) -> person(rs)).optional();
    }

    /** Any person of the home with this name (case-insensitive), dismissed ones included. */
    public Optional<Person> byName(UUID homeId, String name) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM home_people WHERE home_id = :home "
                + "AND lower(display_name) = lower(:name)")
                .param("home", homeId).param("name", name).query((rs, n) -> person(rs)).optional();
    }

    /** The person created from an account of an automatic source (directory, firewall), dismissed ones included. */
    public Optional<Person> byExternalKey(UUID homeId, String origin, String key) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM home_people WHERE home_id = :home AND origin = :origin "
                + "AND external_key = :key")
                .param("home", homeId).param("origin", origin).param("key", key).query((rs, n) -> person(rs))
                .optional();
    }

    public UUID insert(UUID tenantId, UUID homeId, String name, String origin, String externalKey, UUID userId,
            UUID createdBy, Instant now) {
        return jdbc.sql("""
                INSERT INTO home_people (tenant_id, home_id, display_name, user_id, origin, external_key, created_by,
                    created_at, updated_at)
                VALUES (:tenant, :home, :name, :user, :origin, :key, :by, :now, :now) RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("name", name).param("user", userId)
                .param("origin", origin).param("key", externalKey).param("by", createdBy).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    /** An automatic person; empty when a person with the same name appeared meanwhile (concurrent scan). */
    public Optional<UUID> insertAutomatic(UUID tenantId, UUID homeId, String name, String origin, String externalKey,
            Instant now) {
        return jdbc.sql("""
                INSERT INTO home_people (tenant_id, home_id, display_name, origin, external_key, created_at, updated_at)
                VALUES (:tenant, :home, :name, :origin, :key, :now, :now)
                ON CONFLICT DO NOTHING RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("name", name).param("origin", origin)
                .param("key", externalKey).param("now", Sql.ts(now))
                .query(UUID.class).optional();
    }

    /** A dismissed person created again by the user becomes visible (without its old associations). */
    public void restore(UUID id, Instant now) {
        jdbc.sql("UPDATE home_people SET dismissed = false, updated_at = :now WHERE id = :id")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    public void update(UUID id, String name, UUID userId, Instant now) {
        jdbc.sql("UPDATE home_people SET display_name = :name, user_id = :user, updated_at = :now WHERE id = :id")
                .param("id", id).param("name", name).param("user", userId).param("now", Sql.ts(now)).update();
    }

    public void delete(UUID id) {
        jdbc.sql("DELETE FROM home_people WHERE id = :id").param("id", id).update();
    }

    /** Hides an automatic person: its associations are deleted, only the name is kept so it is not created again. */
    public void dismiss(UUID id, Instant now) {
        jdbc.sql("DELETE FROM device_person_assignments WHERE person_id = :id").param("id", id).update();
        jdbc.sql("UPDATE home_people SET dismissed = true, user_id = NULL, updated_at = :now WHERE id = :id")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    /** Non-rejected associations of the visible people of the home, by person. */
    public Map<UUID, List<Assignment>> assignments(UUID homeId) {
        Map<UUID, List<Assignment>> out = new LinkedHashMap<>();
        jdbc.sql("""
                SELECT a.person_id, a.device_id, a.status, a.source, a.evidence, a.updated_at
                FROM device_person_assignments a JOIN home_people p ON p.id = a.person_id
                WHERE p.home_id = :home AND NOT p.dismissed AND a.status <> 'REJECTED'
                ORDER BY a.status, a.updated_at DESC""")
                .param("home", homeId)
                .query((rs, n) -> new Assignment(rs.getObject("person_id", UUID.class),
                        rs.getObject("device_id", UUID.class), rs.getString("status"), rs.getString("source"),
                        rs.getString("evidence"), Sql.instant(rs, "updated_at")))
                .list().forEach(a -> out.computeIfAbsent(a.personId(), k -> new ArrayList<>()).add(a));
        return out;
    }

    /** A decision of a user: CONFIRMED (assign or confirm) or REJECTED (remove: never proposed again). */
    public void decide(UUID tenantId, UUID deviceId, UUID personId, String status, UUID by, Instant now) {
        jdbc.sql("""
                INSERT INTO device_person_assignments (tenant_id, device_id, person_id, status, source, decided_by,
                    created_at, updated_at)
                VALUES (:tenant, :device, :person, :status, 'USER', :by, :now, :now)
                ON CONFLICT (device_id, person_id) DO UPDATE SET status = EXCLUDED.status,
                    decided_by = EXCLUDED.decided_by, updated_at = EXCLUDED.updated_at""")
                .param("tenant", tenantId).param("device", deviceId).param("person", personId).param("status", status)
                .param("by", by).param("now", Sql.ts(now)).update();
    }

    public Optional<String> status(UUID deviceId, UUID personId) {
        return jdbc.sql("SELECT status FROM device_person_assignments WHERE device_id = :device AND person_id = :person")
                .param("device", deviceId).param("person", personId).query(String.class).optional();
    }

    /**
     * An automatic proposal: added as PROBABLE when the pair is new; a pair the user confirmed
     * or rejected is left as it is; a PROBABLE one gets the latest evidence.
     */
    public void propose(UUID tenantId, UUID deviceId, UUID personId, String source, String evidence, Instant now) {
        jdbc.sql("""
                INSERT INTO device_person_assignments (tenant_id, device_id, person_id, status, source, evidence,
                    created_at, updated_at)
                VALUES (:tenant, :device, :person, 'PROBABLE', :source, :evidence, :now, :now)
                ON CONFLICT (device_id, person_id) DO UPDATE SET source = EXCLUDED.source,
                    evidence = EXCLUDED.evidence, updated_at = EXCLUDED.updated_at
                WHERE device_person_assignments.status = 'PROBABLE'""")
                .param("tenant", tenantId).param("device", deviceId).param("person", personId)
                .param("source", source).param("evidence", evidence).param("now", Sql.ts(now)).update();
    }

    /**
     * Names announced by the devices of the home: the current host name, every host name source
     * of the identification (mDNS, NetBIOS, DHCP/router...) and the name given by the user.
     */
    public List<DeviceName> deviceNames(UUID homeId) {
        return jdbc.sql("""
                SELECT d.id, d.tenant_id, d.mac::text AS mac, n.name
                FROM devices d
                CROSS JOIN LATERAL (
                    SELECT d.hostname AS name
                    UNION SELECT d.custom_name
                    UNION SELECT s ->> 'value' FROM device_identifications i, jsonb_array_elements(i.sources) s
                          WHERE i.device_id = d.id AND i.field = 'HOSTNAME') n
                WHERE d.home_id = :home AND n.name IS NOT NULL""")
                .param("home", homeId)
                .query((rs, n) -> new DeviceName(rs.getObject("id", UUID.class), rs.getObject("tenant_id", UUID.class),
                        rs.getString("mac"), rs.getString("name")))
                .list();
    }

    /** Stores an identity of a scan; the same address and source twice keeps the most recent account. */
    public void insertIdentity(UUID tenantId, UUID scanId, ScanIdentity i) {
        jdbc.sql("""
                INSERT INTO scan_identities (tenant_id, scan_id, address, account, source, observed_at)
                VALUES (:tenant, :scan, CAST(:ip AS inet), :account, :source, :at)
                ON CONFLICT (scan_id, address, source) DO UPDATE SET account = EXCLUDED.account,
                    observed_at = EXCLUDED.observed_at
                WHERE EXCLUDED.observed_at > scan_identities.observed_at""")
                .param("tenant", tenantId).param("scan", scanId).param("ip", i.ip()).param("account", i.account())
                .param("source", i.source()).param("at", Sql.ts(i.observedAt())).update();
    }

    /**
     * The identities of a scan with the device that had the same address in that scan (its
     * current address or one of its addresses last seen in that scan); the latest per device and source.
     */
    public List<DeviceIdentity> identitiesOfScan(UUID scanId) {
        return jdbc.sql("""
                SELECT DISTINCT ON (d.id, i.source) d.id, d.tenant_id, host(i.address) AS ip, i.account, i.source,
                    i.observed_at
                FROM scan_identities i
                JOIN devices d ON d.last_scan_id = i.scan_id AND (d.current_ip = i.address OR EXISTS (
                    SELECT 1 FROM device_addresses a
                    WHERE a.device_id = d.id AND a.address = i.address AND a.last_scan_id = i.scan_id))
                WHERE i.scan_id = :scan
                ORDER BY d.id, i.source, i.observed_at DESC""")
                .param("scan", scanId)
                .query((rs, n) -> new DeviceIdentity(rs.getObject("id", UUID.class),
                        rs.getObject("tenant_id", UUID.class), rs.getString("ip"), rs.getString("account"),
                        rs.getString("source"), rs.getTimestamp("observed_at").toInstant()))
                .list();
    }
}
