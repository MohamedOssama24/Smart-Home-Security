package com.shsc.reports;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** PDF reports and the data they are built from (tenant-scoped, under RLS). */
@Repository
public class ReportRepository {

    public record Report(UUID id, UUID tenantId, UUID homeId, UUID scanId, String locale, String status,
            String errorCode, Integer sizeBytes, String sha256, Integer pages, UUID generatedBy, Instant requestedAt,
            Instant generatedAt) {
    }

    public record Content(byte[] bytes, String sha256) {
    }

    /** Score of the scan: the last snapshot computed for it (a triage may have recomputed it). */
    public record ScanScore(Integer score, String riskLevel, String rating, String notComputedReason,
            BigDecimal coverage, boolean provisional, String coverageDetailJson) {
    }

    public record FindingRow(String titleKey, String recommendationKey, String paramsJson, String severity,
            String type, String status, String deviceName, String deviceIp) {
    }

    public record DeviceRow(String name, String ip, String category, String manufacturer) {
    }

    private static final String COLUMNS = """
            id, tenant_id, home_id, scan_id, locale, status, error_code, size_bytes, sha256, pages, generated_by,
            requested_at, generated_at""";

    private final JdbcClient jdbc;

    public ReportRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(UUID tenantId, UUID homeId, UUID scanId, String locale, UUID userId, Instant now) {
        return jdbc.sql("""
                INSERT INTO reports (tenant_id, home_id, scan_id, locale, status, generated_by, requested_at)
                VALUES (:tenant, :home, :scan, :locale, 'PENDING', :user, :now) RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("scan", scanId).param("locale", locale)
                .param("user", userId).param("now", Sql.ts(now)).query(UUID.class).single();
    }

    public Optional<Report> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM reports WHERE id = :id").param("id", id)
                .query((rs, n) -> report(rs)).optional();
    }

    public List<Report> forHome(UUID homeId, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM reports WHERE home_id = :home ORDER BY requested_at DESC, id DESC"
                + " LIMIT :limit").param("home", homeId).param("limit", limit).query((rs, n) -> report(rs)).list();
    }

    public int countSince(UUID homeId, Instant since) {
        return jdbc.sql("SELECT count(*) FROM reports WHERE home_id = :home AND requested_at >= :since")
                .param("home", homeId).param("since", Sql.ts(since)).query(Integer.class).single();
    }

    public boolean pending(UUID scanId, String locale) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM reports WHERE scan_id = :scan AND locale = :locale"
                + " AND status = 'PENDING')").param("scan", scanId).param("locale", locale).query(Boolean.class)
                .single();
    }

    public Optional<Content> content(UUID id) {
        return jdbc.sql("SELECT content, sha256 FROM reports WHERE id = :id AND status = 'READY'").param("id", id)
                .query((rs, n) -> new Content(rs.getBytes("content"), rs.getString("sha256"))).optional();
    }

    public void ready(UUID id, byte[] content, String sha256, int pages, Instant now) {
        jdbc.sql("""
                UPDATE reports SET status = 'READY', content = :content, size_bytes = :size, sha256 = :sha,
                    pages = :pages, generated_at = :now
                WHERE id = :id AND status = 'PENDING'""")
                .param("id", id).param("content", content).param("size", content.length).param("sha", sha256)
                .param("pages", pages).param("now", Sql.ts(now)).update();
    }

    public void failed(UUID id, String errorCode) {
        jdbc.sql("UPDATE reports SET status = 'FAILED', error_code = :code WHERE id = :id AND status = 'PENDING'")
                .param("id", id).param("code", errorCode).update();
    }

    /** Reports still PENDING long after the request (e.g. restart during the generation). */
    public int failStale(Instant before) {
        return jdbc.sql("""
                UPDATE reports SET status = 'FAILED', error_code = 'INTERRUPTED'
                WHERE status = 'PENDING' AND requested_at < :before""")
                .param("before", Sql.ts(before)).update();
    }

    // --- report data --------------------------------------------------------------------------

    public Optional<ScanScore> scanScore(UUID scanId) {
        return jdbc.sql("""
                SELECT score, risk_level, rating, not_computed_reason, coverage, provisional,
                    coverage_detail::text AS coverage_detail
                FROM risk_snapshots WHERE scan_id = :scan ORDER BY computed_at DESC, id DESC LIMIT 1""")
                .param("scan", scanId)
                .query((rs, n) -> new ScanScore((Integer) rs.getObject("score"), rs.getString("risk_level"),
                        rs.getString("rating"), rs.getString("not_computed_reason"), rs.getBigDecimal("coverage"),
                        rs.getBoolean("provisional"), rs.getString("coverage_detail"))).optional();
    }

    /** Findings that are not resolved nor dismissed as false positives, most severe first. */
    public List<FindingRow> findings(UUID homeId) {
        return jdbc.sql("""
                SELECT f.title_key, f.recommendation_key, f.params::text AS params, f.severity, f.finding_type,
                    f.status, coalesce(d.hostname, host(d.current_ip)) AS device_name, host(d.current_ip) AS device_ip
                FROM findings f JOIN devices d ON d.id = f.device_id
                WHERE f.home_id = :home AND f.status IN ('OPEN', 'ACKNOWLEDGED', 'ACCEPTED_RISK')
                ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3 ELSE 4 END, d.current_ip, f.rule_id, f.id""")
                .param("home", homeId)
                .query((rs, n) -> new FindingRow(rs.getString("title_key"), rs.getString("recommendation_key"),
                        rs.getString("params"), rs.getString("severity"), rs.getString("finding_type"),
                        rs.getString("status"), rs.getString("device_name"), rs.getString("device_ip"))).list();
    }

    public List<DeviceRow> devices(UUID homeId) {
        return jdbc.sql("""
                SELECT coalesce(hostname, host(current_ip)) AS name, host(current_ip) AS ip,
                    coalesce(manual_category, detected_category) AS category, manufacturer
                FROM devices WHERE home_id = :home ORDER BY current_ip""")
                .param("home", homeId)
                .query((rs, n) -> new DeviceRow(rs.getString("name"), rs.getString("ip"), rs.getString("category"),
                        rs.getString("manufacturer"))).list();
    }

    private static Report report(ResultSet rs) throws SQLException {
        return new Report(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "home_id"),
                Sql.uuid(rs, "scan_id"), rs.getString("locale"), rs.getString("status"), rs.getString("error_code"),
                (Integer) rs.getObject("size_bytes"), rs.getString("sha256"), (Integer) rs.getObject("pages"),
                Sql.uuid(rs, "generated_by"), Sql.instant(rs, "requested_at"), Sql.instant(rs, "generated_at"));
    }
}
