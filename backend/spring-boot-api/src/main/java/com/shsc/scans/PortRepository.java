package com.shsc.scans;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/**
 * Open ports, detected services and detected protocols (docs/18-PORT-SCANNING.md). Only the
 * OPEN ports are stored; the per-host counters are the PORTSCAN observation of the scan.
 * RLS: current tenant.
 */
@Repository
public class PortRepository {

    /** Service identified on a port; evidence and tls are JSON objects (or null). */
    public record Service(String name, String product, String version, String status, String confidence,
            String evidenceJson, String tlsJson) {
    }

    /** A port as uploaded by the agent. */
    public record Port(String ip, String protocol, int port, String state, String reason, Instant observedAt,
            Service service) {
    }

    /** A stored port of a scan, with its service (null when none was identified). */
    public record StoredPort(UUID id, UUID scanId, UUID deviceId, String ip, String protocol, int port, String state,
            String reason, Instant observedAt, Service service) {
    }

    public record Protocol(String protocol, String detailsJson, String confidence) {
    }

    private static final String SELECT = """
            SELECT p.id, p.scan_id, p.device_id, host(p.ip) AS ip, p.protocol, p.port, p.state, p.reason,
                p.observed_at, s.name, s.product, s.version, s.status, s.confidence, s.evidence::text AS evidence,
                s.tls::text AS tls
            FROM open_ports p LEFT JOIN detected_services s ON s.open_port_id = p.id""";

    private final JdbcClient jdbc;

    public PortRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Stores one port and its service (a repeated upload of the same port replaces them). */
    public void insert(UUID tenantId, UUID scanId, Port p) {
        UUID id = jdbc.sql("""
                INSERT INTO open_ports (tenant_id, scan_id, ip, protocol, port, state, reason, observed_at)
                VALUES (:tenant, :scan, CAST(:ip AS inet), :protocol, :port, :state, :reason, :at)
                ON CONFLICT (scan_id, ip, protocol, port) DO UPDATE SET state = EXCLUDED.state,
                    reason = EXCLUDED.reason, observed_at = EXCLUDED.observed_at
                RETURNING id""")
                .param("tenant", tenantId).param("scan", scanId).param("ip", p.ip()).param("protocol", p.protocol())
                .param("port", p.port()).param("state", p.state()).param("reason", p.reason())
                .param("at", Sql.ts(p.observedAt()))
                .query(UUID.class).single();
        Service s = p.service();
        if (s == null) {
            jdbc.sql("DELETE FROM detected_services WHERE open_port_id = :id").param("id", id).update();
            return;
        }
        jdbc.sql("""
                INSERT INTO detected_services (tenant_id, open_port_id, name, product, version, status, confidence,
                    evidence, tls)
                VALUES (:tenant, :port, :name, :product, :version, :status, :confidence,
                    COALESCE(CAST(:evidence AS jsonb), '{}'), CAST(:tls AS jsonb))
                ON CONFLICT (open_port_id) DO UPDATE SET name = EXCLUDED.name, product = EXCLUDED.product,
                    version = EXCLUDED.version, status = EXCLUDED.status, confidence = EXCLUDED.confidence,
                    evidence = EXCLUDED.evidence, tls = EXCLUDED.tls""")
                .param("tenant", tenantId).param("port", id).param("name", s.name()).param("product", s.product())
                .param("version", s.version()).param("status", s.status()).param("confidence", s.confidence())
                .param("evidence", s.evidenceJson()).param("tls", s.tlsJson())
                .update();
    }

    public List<StoredPort> ofScan(UUID scanId) {
        return jdbc.sql(SELECT + " WHERE p.scan_id = :scan ORDER BY p.ip, p.protocol, p.port")
                .param("scan", scanId).query(PortRepository::map).list();
    }

    /** Ports of a device found by one scan. */
    public List<StoredPort> ofDevice(UUID deviceId, UUID scanId) {
        return jdbc.sql(SELECT + " WHERE p.device_id = :device AND p.scan_id = :scan ORDER BY p.protocol, p.port")
                .param("device", deviceId).param("scan", scanId).query(PortRepository::map).list();
    }

    /** Last scan that scanned the ports of the device (its PORTSCAN observation) and its counters. */
    public Optional<PortScan> lastPortScan(UUID deviceId) {
        return jdbc.sql("""
                SELECT scan_id, details::text AS details, observed_at FROM scan_observations
                WHERE device_id = :device AND method = 'PORTSCAN' ORDER BY observed_at DESC, id DESC LIMIT 1""")
                .param("device", deviceId)
                .query((rs, n) -> new PortScan(Sql.uuid(rs, "scan_id"), rs.getString("details"),
                        Sql.instant(rs, "observed_at")))
                .optional();
    }

    public record PortScan(UUID scanId, String summaryJson, Instant observedAt) {
    }

    public void linkToDevice(UUID scanId, List<String> addresses, UUID deviceId) {
        jdbc.sql("""
                UPDATE open_ports SET device_id = :device
                WHERE scan_id = :scan AND host(ip) = ANY (CAST(:addresses AS text[]))""")
                .param("scan", scanId).param("device", deviceId)
                .param("addresses", "{" + String.join(",", addresses.stream().map(a -> "\"" + a + "\"").toList()) + "}")
                .update();
    }

    /** Replaces the protocols detected for the device by this scan. */
    public void replaceProtocols(UUID tenantId, UUID deviceId, UUID scanId, List<Protocol> protocols) {
        jdbc.sql("DELETE FROM detected_protocols WHERE device_id = :device AND scan_id = :scan")
                .param("device", deviceId).param("scan", scanId).update();
        for (Protocol p : protocols) {
            jdbc.sql("""
                    INSERT INTO detected_protocols (tenant_id, device_id, scan_id, protocol, details, confidence)
                    VALUES (:tenant, :device, :scan, :protocol, CAST(:details AS jsonb), :confidence)""")
                    .param("tenant", tenantId).param("device", deviceId).param("scan", scanId)
                    .param("protocol", p.protocol()).param("details", p.detailsJson())
                    .param("confidence", p.confidence()).update();
        }
    }

    public List<Protocol> protocols(UUID deviceId, UUID scanId) {
        return jdbc.sql("""
                SELECT protocol, details::text AS details, confidence FROM detected_protocols
                WHERE device_id = :device AND scan_id = :scan ORDER BY protocol""")
                .param("device", deviceId).param("scan", scanId)
                .query((rs, n) -> new Protocol(rs.getString("protocol"), rs.getString("details"),
                        rs.getString("confidence")))
                .list();
    }

    private static StoredPort map(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        String name = rs.getString("name");
        Service service = name == null ? null : new Service(name, rs.getString("product"), rs.getString("version"),
                rs.getString("status"), rs.getString("confidence"), rs.getString("evidence"), rs.getString("tls"));
        return new StoredPort(Sql.uuid(rs, "id"), Sql.uuid(rs, "scan_id"), Sql.uuid(rs, "device_id"),
                rs.getString("ip"), rs.getString("protocol"), rs.getInt("port"), rs.getString("state"),
                rs.getString("reason"), Sql.instant(rs, "observed_at"), service);
    }
}
