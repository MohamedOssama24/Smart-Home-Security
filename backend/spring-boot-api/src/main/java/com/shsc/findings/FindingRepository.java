package com.shsc.findings;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Findings, their evidence and the CVEs matched to devices (RLS: current tenant). */
@Repository
public class FindingRepository {

    public record Finding(UUID id, UUID tenantId, UUID homeId, UUID deviceId, String ruleId, int ruleVersion,
            String fingerprint, String titleKey, String recommendationKey, String paramsJson, String severity,
            String type, String confidence, String source, String protocol, Integer port, String cveId,
            String status, String statusReason, UUID statusChangedBy, Instant statusChangedAt,
            Instant firstDetectedAt, Instant lastDetectedAt, Instant resolvedAt, UUID firstScanId, UUID lastScanId,
            String deviceName, String deviceIp, String deviceCategory) {
    }

    /** Values written at each detection. */
    public record Detected(String ruleId, int ruleVersion, String titleKey, String recommendationKey,
            String paramsJson, String severity, String type, String confidence, String source, String protocol,
            Integer port, String cveId) {
    }

    public record Evidence(UUID scanId, String type, String dataJson, Instant collectedAt) {
    }

    public record DeviceVulnerability(String cveId, String matchQuality, String matchedCpe, String product,
            String version) {
    }

    /** Observation of a scan already linked to its device. */
    public record DeviceObservation(UUID deviceId, String method, String detailsJson) {
    }

    public record Filter(String status, String severity, String type) {
    }

    public record HomeVulnerability(String cveId, String matchQuality, String product, String version,
            UUID findingId, String findingStatus, String findingType, UUID deviceId, String deviceName,
            String deviceIp, String severity, java.math.BigDecimal cvssScore, boolean kev,
            java.math.BigDecimal epssScore) {
    }

    private static final String SELECT = """
            SELECT f.*, COALESCE(d.hostname, host(d.current_ip)) AS device_name, host(d.current_ip) AS device_ip,
                COALESCE(d.manual_category, d.detected_category) AS device_category
            FROM findings f JOIN devices d ON d.id = f.device_id""";

    private static final String SEVERITY_RANK = """
            CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3
                ELSE 4 END""";

    private final JdbcClient jdbc;

    public FindingRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<DeviceObservation> observations(UUID scanId) {
        return jdbc.sql("""
                SELECT device_id, method, details::text AS details FROM scan_observations
                WHERE scan_id = :scan ORDER BY device_id, method""")
                .param("scan", scanId)
                .query((rs, n) -> new DeviceObservation(Sql.uuid(rs, "device_id"), rs.getString("method"),
                        rs.getString("details")))
                .list();
    }

    public Optional<Finding> lockByFingerprint(UUID deviceId, String fingerprint) {
        return jdbc.sql(SELECT + " WHERE f.device_id = :device AND f.fingerprint = :fp FOR UPDATE OF f")
                .param("device", deviceId).param("fp", fingerprint).query(FindingRepository::map).optional();
    }

    public UUID insert(UUID tenantId, UUID homeId, UUID deviceId, String fingerprint, Detected d, UUID scanId,
            Instant now) {
        return jdbc.sql("""
                INSERT INTO findings (tenant_id, home_id, device_id, rule_id, rule_version, fingerprint, title_key,
                    recommendation_key, params, severity, finding_type, confidence, source, protocol, port, cve_id,
                    first_detected_at, last_detected_at, first_scan_id, last_scan_id)
                VALUES (:tenant, :home, :device, :rule, :ruleVersion, :fp, :title, :recommendation,
                    CAST(:params AS jsonb), :severity, :type, :confidence, :source, :protocol, :port, :cve,
                    :now, :now, :scan, :scan)
                RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("device", deviceId)
                .param("rule", d.ruleId()).param("ruleVersion", d.ruleVersion()).param("fp", fingerprint)
                .param("title", d.titleKey()).param("recommendation", d.recommendationKey())
                .param("params", d.paramsJson()).param("severity", d.severity()).param("type", d.type())
                .param("confidence", d.confidence()).param("source", d.source()).param("protocol", d.protocol())
                .param("port", d.port()).param("cve", d.cveId()).param("now", Sql.ts(now)).param("scan", scanId)
                .query(UUID.class).single();
    }

    /** Detected again: current values; a RESOLVED finding is OPEN again (triage decisions are kept). */
    public void redetected(UUID id, Detected d, UUID scanId, Instant now) {
        jdbc.sql("""
                UPDATE findings SET rule_version = :ruleVersion, title_key = :title,
                    recommendation_key = :recommendation, params = CAST(:params AS jsonb), severity = :severity,
                    finding_type = :type, confidence = :confidence, source = :source, last_detected_at = :now,
                    last_scan_id = :scan,
                    status = CASE WHEN status = 'RESOLVED' THEN 'OPEN' ELSE status END,
                    status_changed_at = CASE WHEN status = 'RESOLVED' THEN :now ELSE status_changed_at END,
                    status_changed_by = CASE WHEN status = 'RESOLVED' THEN NULL ELSE status_changed_by END,
                    status_reason = CASE WHEN status = 'RESOLVED' THEN NULL ELSE status_reason END,
                    resolved_at = NULL, version = version + 1
                WHERE id = :id""")
                .param("id", id).param("ruleVersion", d.ruleVersion()).param("title", d.titleKey())
                .param("recommendation", d.recommendationKey()).param("params", d.paramsJson())
                .param("severity", d.severity()).param("type", d.type()).param("confidence", d.confidence())
                .param("source", d.source()).param("now", Sql.ts(now)).param("scan", scanId).update();
    }

    /** Findings of the device that a later scan may resolve (OPEN and ACKNOWLEDGED). */
    public List<Finding> active(UUID deviceId) {
        return jdbc.sql(SELECT + " WHERE f.device_id = :device AND f.status IN ('OPEN', 'ACKNOWLEDGED') FOR UPDATE OF f")
                .param("device", deviceId).query(FindingRepository::map).list();
    }

    public void resolve(UUID id, UUID scanId, Instant now) {
        jdbc.sql("""
                UPDATE findings SET status = 'RESOLVED', resolved_at = :now, status_changed_at = :now,
                    status_changed_by = NULL, status_reason = NULL, last_scan_id = :scan, version = version + 1
                WHERE id = :id""")
                .param("id", id).param("now", Sql.ts(now)).param("scan", scanId).update();
        jdbc.sql("DELETE FROM device_vulnerabilities WHERE finding_id = :id").param("id", id).update();
    }

    public void addEvidence(UUID tenantId, UUID findingId, UUID scanId, String type, String dataJson, Instant now) {
        jdbc.sql("""
                INSERT INTO finding_evidence (tenant_id, finding_id, scan_id, type, data, collected_at)
                VALUES (:tenant, :finding, :scan, :type, CAST(:data AS jsonb), :now)
                ON CONFLICT (finding_id, scan_id) DO UPDATE SET type = EXCLUDED.type, data = EXCLUDED.data,
                    collected_at = EXCLUDED.collected_at""")
                .param("tenant", tenantId).param("finding", findingId).param("scan", scanId).param("type", type)
                .param("data", dataJson).param("now", Sql.ts(now)).update();
    }

    public void replaceVulnerabilities(UUID tenantId, UUID deviceId, UUID findingId, UUID scanId,
            List<DeviceVulnerability> rows) {
        jdbc.sql("DELETE FROM device_vulnerabilities WHERE finding_id = :id").param("id", findingId).update();
        for (DeviceVulnerability v : rows) {
            jdbc.sql("""
                    INSERT INTO device_vulnerabilities (tenant_id, device_id, cve_id, finding_id, match_quality,
                        matched_cpe, product, version, scan_id)
                    VALUES (:tenant, :device, :cve, :finding, :quality, :cpe, :product, :version, :scan)
                    ON CONFLICT (device_id, cve_id, finding_id) DO NOTHING""")
                    .param("tenant", tenantId).param("device", deviceId).param("cve", v.cveId())
                    .param("finding", findingId).param("quality", v.matchQuality()).param("cpe", v.matchedCpe())
                    .param("product", v.product()).param("version", v.version()).param("scan", scanId).update();
        }
    }

    public List<Finding> forHome(UUID homeId, Filter filter, int limit) {
        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE f.home_id = :home");
        List<Object[]> params = new ArrayList<>();
        if (filter.status() != null) {
            sql.append(" AND f.status = :status");
            params.add(new Object[] { "status", filter.status() });
        }
        if (filter.severity() != null) {
            sql.append(" AND f.severity = :severity");
            params.add(new Object[] { "severity", filter.severity() });
        }
        if (filter.type() != null) {
            sql.append(" AND f.finding_type = :type");
            params.add(new Object[] { "type", filter.type() });
        }
        sql.append(" ORDER BY CASE WHEN f.status IN ('OPEN', 'ACKNOWLEDGED') THEN 0 ELSE 1 END, ")
                .append(SEVERITY_RANK).append(", f.last_detected_at DESC, f.id LIMIT :limit");
        JdbcClient.StatementSpec spec = jdbc.sql(sql.toString()).param("home", homeId).param("limit", limit);
        for (Object[] p : params) {
            spec = spec.param((String) p[0], p[1]);
        }
        return spec.query(FindingRepository::map).list();
    }

    public Optional<Finding> find(UUID id) {
        return jdbc.sql(SELECT + " WHERE f.id = :id").param("id", id).query(FindingRepository::map).optional();
    }

    public Optional<Finding> lock(UUID id) {
        return jdbc.sql(SELECT + " WHERE f.id = :id FOR UPDATE OF f").param("id", id).query(FindingRepository::map)
                .optional();
    }

    public void setStatus(UUID id, String status, String reason, UUID by, Instant now) {
        jdbc.sql("""
                UPDATE findings SET status = :status, status_reason = :reason, status_changed_by = :by,
                    status_changed_at = :now, version = version + 1
                WHERE id = :id""")
                .param("id", id).param("status", status).param("reason", reason).param("by", by)
                .param("now", Sql.ts(now)).update();
    }

    public List<Evidence> evidence(UUID findingId, int limit) {
        return jdbc.sql("""
                SELECT scan_id, type, data::text AS data, collected_at FROM finding_evidence
                WHERE finding_id = :id ORDER BY collected_at DESC LIMIT :limit""")
                .param("id", findingId).param("limit", limit)
                .query((rs, n) -> new Evidence(Sql.uuid(rs, "scan_id"), rs.getString("type"), rs.getString("data"),
                        Sql.instant(rs, "collected_at")))
                .list();
    }

    public List<DeviceVulnerability> vulnerabilities(UUID findingId) {
        return jdbc.sql("""
                SELECT dv.cve_id, dv.match_quality, dv.matched_cpe, dv.product, dv.version
                FROM device_vulnerabilities dv LEFT JOIN vulnerabilities v ON v.cve_id = dv.cve_id
                WHERE dv.finding_id = :id ORDER BY v.cvss_score DESC NULLS LAST, dv.cve_id""")
                .param("id", findingId)
                .query((rs, n) -> new DeviceVulnerability(rs.getString("cve_id"), rs.getString("match_quality"),
                        rs.getString("matched_cpe"), rs.getString("product"), rs.getString("version")))
                .list();
    }

    /** CVEs matched to the devices of a home (non-resolved findings), most severe first. */
    public List<HomeVulnerability> forHomeVulnerabilities(UUID homeId, int limit) {
        return jdbc.sql("""
                SELECT dv.cve_id, dv.match_quality, dv.product, dv.version, dv.finding_id, f.status AS finding_status,
                    f.finding_type, f.device_id, COALESCE(d.hostname, host(d.current_ip)) AS device_name,
                    host(d.current_ip) AS device_ip, v.severity, v.cvss_score, k.cve_id IS NOT NULL AS kev,
                    e.score AS epss_score
                FROM device_vulnerabilities dv
                JOIN findings f ON f.id = dv.finding_id
                JOIN devices d ON d.id = dv.device_id
                JOIN vulnerabilities v ON v.cve_id = dv.cve_id
                LEFT JOIN vulnerability_kev k ON k.cve_id = dv.cve_id
                LEFT JOIN vulnerability_epss e ON e.cve_id = dv.cve_id
                WHERE f.home_id = :home AND f.status <> 'RESOLVED'
                ORDER BY (k.cve_id IS NOT NULL) DESC, v.cvss_score DESC NULLS LAST, dv.cve_id, device_name
                LIMIT :limit""")
                .param("home", homeId).param("limit", limit)
                .query((rs, n) -> new HomeVulnerability(rs.getString("cve_id"), rs.getString("match_quality"),
                        rs.getString("product"), rs.getString("version"), Sql.uuid(rs, "finding_id"),
                        rs.getString("finding_status"), rs.getString("finding_type"), Sql.uuid(rs, "device_id"),
                        rs.getString("device_name"), rs.getString("device_ip"), rs.getString("severity"),
                        rs.getBigDecimal("cvss_score"), rs.getBoolean("kev"), rs.getBigDecimal("epss_score")))
                .list();
    }

    private static Finding map(ResultSet rs, int row) throws SQLException {
        int port = rs.getInt("port");
        Integer portValue = rs.wasNull() ? null : port;
        return new Finding(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "home_id"),
                Sql.uuid(rs, "device_id"), rs.getString("rule_id"), rs.getInt("rule_version"),
                rs.getString("fingerprint"), rs.getString("title_key"), rs.getString("recommendation_key"),
                rs.getString("params"), rs.getString("severity"), rs.getString("finding_type"),
                rs.getString("confidence"), rs.getString("source"), rs.getString("protocol"), portValue,
                rs.getString("cve_id"), rs.getString("status"), rs.getString("status_reason"),
                Sql.uuid(rs, "status_changed_by"), Sql.instant(rs, "status_changed_at"),
                Sql.instant(rs, "first_detected_at"), Sql.instant(rs, "last_detected_at"),
                Sql.instant(rs, "resolved_at"), Sql.uuid(rs, "first_scan_id"), Sql.uuid(rs, "last_scan_id"),
                rs.getString("device_name"), rs.getString("device_ip"), rs.getString("device_category"));
    }
}
