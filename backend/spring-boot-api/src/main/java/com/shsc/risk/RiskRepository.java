package com.shsc.risk;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Risk snapshots (insert only) and the non-resolved findings of a home the score is computed from. */
@Repository
public class RiskRepository {

    public record Snapshot(UUID id, UUID tenantId, UUID homeId, UUID scanId, String scanProfile, String trigger,
            Integer score, String riskLevel, String rating, String notComputedReason, BigDecimal coverage,
            String coverageDetailJson, boolean provisional, String breakdownJson, String topDevicesJson,
            String deltaJson, Instant computedAt, String engineVersion) {
    }

    /** History row: no breakdown. */
    public record Summary(UUID id, UUID scanId, String scanProfile, String trigger, Integer score, String riskLevel,
            String rating, String notComputedReason, BigDecimal coverage, boolean provisional, Integer scoreChange,
            Instant computedAt, String engineVersion) {
    }

    public record NewSnapshot(UUID tenantId, UUID homeId, UUID scanId, String trigger, Integer score,
            String riskLevel, String rating, String notComputedReason, BigDecimal coverage, String coverageDetailJson,
            boolean provisional, String breakdownJson, String topDevicesJson, String deltaJson, Instant computedAt,
            String engineVersion) {
    }

    /** Non-resolved finding with whether its CVE is in the KEV catalog now. */
    public record OpenFinding(UUID id, UUID deviceId, String ruleId, String titleKey, String paramsJson,
            String severity, String type, String confidence, String status, String cveId, boolean kev) {
    }

    private static final String SELECT = """
            SELECT r.*, s.profile AS scan_profile FROM risk_snapshots r JOIN scans s ON s.id = r.scan_id""";

    private final JdbcClient jdbc;

    public RiskRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(NewSnapshot s) {
        return jdbc.sql("""
                INSERT INTO risk_snapshots (tenant_id, home_id, scan_id, trigger, score, risk_level, rating,
                    not_computed_reason, coverage, coverage_detail, provisional, breakdown, top_devices,
                    delta_from_previous, computed_at, engine_version)
                VALUES (:tenant, :home, :scan, :trigger, :score, :level, :rating, :reason, :coverage,
                    CAST(:coverageDetail AS jsonb), :provisional, CAST(:breakdown AS jsonb), CAST(:top AS jsonb),
                    CAST(:delta AS jsonb), :at, :engine)
                RETURNING id""")
                .param("tenant", s.tenantId()).param("home", s.homeId()).param("scan", s.scanId())
                .param("trigger", s.trigger()).param("score", s.score()).param("level", s.riskLevel())
                .param("rating", s.rating()).param("reason", s.notComputedReason()).param("coverage", s.coverage())
                .param("coverageDetail", s.coverageDetailJson()).param("provisional", s.provisional())
                .param("breakdown", s.breakdownJson()).param("top", s.topDevicesJson()).param("delta", s.deltaJson())
                .param("at", Sql.ts(s.computedAt())).param("engine", s.engineVersion())
                .query(UUID.class).single();
    }

    /** Latest snapshot of the home, computed or not. */
    public Optional<Snapshot> latest(UUID homeId) {
        return jdbc.sql(SELECT + " WHERE r.home_id = :home ORDER BY r.computed_at DESC, r.id DESC LIMIT 1")
                .param("home", homeId).query(RiskRepository::map).optional();
    }

    /** Latest snapshot of the home that has a score. */
    public Optional<Snapshot> latestScored(UUID homeId) {
        return jdbc.sql(SELECT
                + " WHERE r.home_id = :home AND r.score IS NOT NULL ORDER BY r.computed_at DESC, r.id DESC LIMIT 1")
                .param("home", homeId).query(RiskRepository::map).optional();
    }

    public List<Summary> history(UUID homeId, int limit) {
        return jdbc.sql("""
                SELECT r.id, r.scan_id, s.profile AS scan_profile, r.trigger, r.score, r.risk_level, r.rating,
                    r.not_computed_reason, r.coverage, r.provisional,
                    (r.delta_from_previous ->> 'scoreChange')::integer AS score_change, r.computed_at, r.engine_version
                FROM risk_snapshots r JOIN scans s ON s.id = r.scan_id
                WHERE r.home_id = :home ORDER BY r.computed_at DESC, r.id DESC LIMIT :limit""")
                .param("home", homeId).param("limit", limit)
                .query((rs, n) -> new Summary(Sql.uuid(rs, "id"), Sql.uuid(rs, "scan_id"), rs.getString("scan_profile"),
                        rs.getString("trigger"), integer(rs, "score"), rs.getString("risk_level"),
                        rs.getString("rating"), rs.getString("not_computed_reason"), rs.getBigDecimal("coverage"),
                        rs.getBoolean("provisional"), integer(rs, "score_change"), Sql.instant(rs, "computed_at"),
                        rs.getString("engine_version")))
                .list();
    }

    public List<OpenFinding> openFindings(UUID homeId) {
        return jdbc.sql("""
                SELECT f.id, f.device_id, f.rule_id, f.title_key, f.params::text AS params, f.severity,
                    f.finding_type, f.confidence, f.status, f.cve_id,
                    EXISTS (SELECT 1 FROM vulnerability_kev k WHERE k.cve_id = f.cve_id) AS kev
                FROM findings f WHERE f.home_id = :home AND f.status <> 'RESOLVED'
                ORDER BY f.id""")
                .param("home", homeId)
                .query((rs, n) -> new OpenFinding(Sql.uuid(rs, "id"), Sql.uuid(rs, "device_id"), rs.getString("rule_id"),
                        rs.getString("title_key"), rs.getString("params"), rs.getString("severity"),
                        rs.getString("finding_type"), rs.getString("confidence"), rs.getString("status"),
                        rs.getString("cve_id"), rs.getBoolean("kev")))
                .list();
    }

    /** Current status of findings (to explain why a finding no longer counts). */
    public Map<UUID, String> statuses(List<UUID> ids) {
        Map<UUID, String> out = new HashMap<>();
        if (!ids.isEmpty()) {
            jdbc.sql("SELECT id, status FROM findings WHERE id IN (:ids)").param("ids", ids)
                    .query(rs -> {
                        out.put(Sql.uuid(rs, "id"), rs.getString("status"));
                    });
        }
        return out;
    }

    private static Snapshot map(ResultSet rs, int n) throws SQLException {
        return new Snapshot(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "home_id"),
                Sql.uuid(rs, "scan_id"), rs.getString("scan_profile"), rs.getString("trigger"), integer(rs, "score"),
                rs.getString("risk_level"), rs.getString("rating"), rs.getString("not_computed_reason"),
                rs.getBigDecimal("coverage"), rs.getString("coverage_detail"), rs.getBoolean("provisional"),
                rs.getString("breakdown"), rs.getString("top_devices"), rs.getString("delta_from_previous"),
                Sql.instant(rs, "computed_at"), rs.getString("engine_version"));
    }

    private static Integer integer(ResultSet rs, String column) throws SQLException {
        int v = rs.getInt(column);
        return rs.wasNull() ? null : v;
    }
}
