package com.shsc.integrations;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/**
 * Read-only inventory of Home Assistant uploaded with the scan results (docs/24-INTEGRATIONS.md).
 * The URL and the token of Home Assistant never reach the backend. RLS: current tenant.
 */
@Repository
public class HomeAssistantRepository {

    /** A device known to Home Assistant; macs are lower-case "aa:bb:cc:dd:ee:ff". */
    public record GatewayDevice(String name, String manufacturer, String model, String swVersion, String protocol,
            List<String> macs, int entityCount) {
    }

    /** The instance seen by a scan. */
    public record Inventory(String ip, String version, boolean https, Instant observedAt, List<GatewayDevice> devices,
            boolean truncated) {
    }

    /** A stored device, with the address of the scanned host that has one of its MAC addresses. */
    public record StoredDevice(GatewayDevice device, String matchedIp) {
    }

    public record Stored(String ip, String version, boolean https, int deviceCount, boolean truncated,
            Instant observedAt, List<StoredDevice> devices) {
    }

    private final JdbcClient jdbc;

    public HomeAssistantRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Stores the inventory of a scan; false when the scan already has one (idempotent). */
    public boolean insert(UUID tenantId, UUID scanId, Inventory inv) {
        int rows = jdbc.sql("""
                INSERT INTO scan_home_assistant (scan_id, tenant_id, ip, version, https, device_count, truncated,
                    observed_at)
                VALUES (:scan, :tenant, CAST(:ip AS inet), :version, :https, :count, :truncated, :at)
                ON CONFLICT (scan_id) DO NOTHING""")
                .param("scan", scanId).param("tenant", tenantId).param("ip", inv.ip()).param("version", inv.version())
                .param("https", inv.https()).param("count", inv.devices().size()).param("truncated", inv.truncated())
                .param("at", Sql.ts(inv.observedAt()))
                .update();
        if (rows == 0) {
            return false;
        }
        int position = 0;
        for (GatewayDevice d : inv.devices()) {
            jdbc.sql("""
                    INSERT INTO scan_gateway_devices (tenant_id, scan_id, source, position, name, manufacturer, model,
                        sw_version, protocol, macs, entity_count)
                    VALUES (:tenant, :scan, 'HOME_ASSISTANT', :position, :name, :manufacturer, :model, :sw,
                        :protocol, string_to_array(:macs, ','), :entities)""")
                    .param("tenant", tenantId).param("scan", scanId).param("position", position++)
                    .param("name", d.name()).param("manufacturer", d.manufacturer()).param("model", d.model())
                    .param("sw", d.swVersion()).param("protocol", d.protocol())
                    .param("macs", String.join(",", d.macs())).param("entities", d.entityCount())
                    .update();
        }
        return true;
    }

    /** The inventory of a scan; each device is matched by MAC to the hosts observed by the same scan. */
    public Optional<Stored> ofScan(UUID scanId) {
        return jdbc.sql("""
                SELECT host(ip) AS ip, version, https, device_count, truncated, observed_at
                FROM scan_home_assistant WHERE scan_id = :scan""")
                .param("scan", scanId)
                .query((rs, n) -> new Stored(rs.getString("ip"), rs.getString("version"), rs.getBoolean("https"),
                        rs.getInt("device_count"), rs.getBoolean("truncated"), Sql.instant(rs, "observed_at"),
                        devices(scanId)))
                .optional();
    }

    /** Devices of the Home Assistant registry of a scan by each of their MACs (M20 identification). */
    public java.util.Map<String, GatewayDevice> devicesByMac(UUID scanId) {
        java.util.Map<String, GatewayDevice> out = new java.util.HashMap<>();
        for (StoredDevice d : devices(scanId)) {
            d.device().macs().forEach(m -> out.putIfAbsent(m.toLowerCase(java.util.Locale.ROOT), d.device()));
        }
        return out;
    }

    private List<StoredDevice> devices(UUID scanId) {
        return jdbc.sql("""
                SELECT g.name, g.manufacturer, g.model, g.sw_version, g.protocol, array_to_string(g.macs, ',') AS macs,
                    g.entity_count,
                    (SELECT host(o.ip) FROM scan_observations o
                     WHERE o.scan_id = g.scan_id AND o.mac IS NOT NULL AND o.mac::text = ANY (g.macs)
                     ORDER BY family(o.ip), o.ip LIMIT 1) AS matched_ip
                FROM scan_gateway_devices g WHERE g.scan_id = :scan ORDER BY g.position""")
                .param("scan", scanId)
                .query((rs, n) -> {
                    String macs = rs.getString("macs");
                    return new StoredDevice(new GatewayDevice(rs.getString("name"), rs.getString("manufacturer"),
                            rs.getString("model"), rs.getString("sw_version"), rs.getString("protocol"),
                            macs == null || macs.isEmpty() ? List.of() : List.of(macs.split(",")),
                            rs.getInt("entity_count")), rs.getString("matched_ip"));
                })
                .list();
    }
}
