package com.shsc.overview;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/**
 * Per-home figures of the overview, read in bulk (one query per figure, not per home). The
 * caller passes only homes the user may read; RLS keeps every query inside the tenant.
 */
@Repository
public class OverviewRepository {

    /** Latest snapshot (computed or not) and the latest one with a score. */
    public record RiskFigures(Integer score, String riskLevel, String rating, boolean provisional,
            BigDecimal coverage, Integer scoreChange, Instant computedAt, String currentNotComputedReason) {
    }

    /** Counted findings (OPEN, ACKNOWLEDGED) by severity and how many have a CVE in the KEV catalog. */
    public record FindingFigures(Map<String, Integer> bySeverity, int kev) {
    }

    private final JdbcClient jdbc;

    public OverviewRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Map<UUID, RiskFigures> risk(Collection<UUID> homeIds) {
        Map<UUID, RiskFigures> out = new HashMap<>();
        if (homeIds.isEmpty()) {
            return out;
        }
        jdbc.sql("""
                WITH cur AS (
                    SELECT DISTINCT ON (home_id) home_id, not_computed_reason
                    FROM risk_snapshots WHERE home_id IN (:homes)
                    ORDER BY home_id, computed_at DESC, id DESC),
                scored AS (
                    SELECT DISTINCT ON (home_id) home_id, score, risk_level, rating, provisional, coverage,
                        (delta_from_previous ->> 'scoreChange')::integer AS score_change, computed_at
                    FROM risk_snapshots WHERE home_id IN (:homes) AND score IS NOT NULL
                    ORDER BY home_id, computed_at DESC, id DESC)
                SELECT cur.home_id, cur.not_computed_reason, scored.score,
                    scored.risk_level, scored.rating, scored.provisional, scored.coverage, scored.score_change,
                    scored.computed_at
                FROM cur LEFT JOIN scored ON scored.home_id = cur.home_id""")
                .param("homes", homeIds)
                .query(rs -> {
                    int score = rs.getInt("score");
                    Integer scoreValue = rs.wasNull() ? null : score;
                    int change = rs.getInt("score_change");
                    Integer changeValue = rs.wasNull() ? null : change;
                    out.put(Sql.uuid(rs, "home_id"), new RiskFigures(scoreValue, rs.getString("risk_level"),
                            rs.getString("rating"), rs.getBoolean("provisional"), rs.getBigDecimal("coverage"),
                            changeValue, Sql.instant(rs, "computed_at"), rs.getString("not_computed_reason")));
                });
        return out;
    }

    public Map<UUID, FindingFigures> findings(Collection<UUID> homeIds) {
        Map<UUID, Map<String, Integer>> bySeverity = new HashMap<>();
        Map<UUID, Integer> kev = new HashMap<>();
        if (!homeIds.isEmpty()) {
            jdbc.sql("""
                    SELECT f.home_id, f.severity, count(*) AS n,
                        count(*) FILTER (WHERE EXISTS (SELECT 1 FROM vulnerability_kev k WHERE k.cve_id = f.cve_id))
                            AS kev
                    FROM findings f
                    WHERE f.home_id IN (:homes) AND f.status IN ('OPEN', 'ACKNOWLEDGED')
                    GROUP BY f.home_id, f.severity""")
                    .param("homes", homeIds)
                    .query(rs -> {
                        UUID home = Sql.uuid(rs, "home_id");
                        bySeverity.computeIfAbsent(home, h -> new HashMap<>()).put(rs.getString("severity"),
                                rs.getInt("n"));
                        kev.merge(home, rs.getInt("kev"), Integer::sum);
                    });
        }
        Map<UUID, FindingFigures> out = new HashMap<>();
        for (UUID home : homeIds) {
            out.put(home, new FindingFigures(bySeverity.getOrDefault(home, Map.of()), kev.getOrDefault(home, 0)));
        }
        return out;
    }

    public Map<UUID, Integer> deviceCounts(Collection<UUID> homeIds) {
        Map<UUID, Integer> out = new HashMap<>();
        if (!homeIds.isEmpty()) {
            jdbc.sql("SELECT home_id, count(*) AS n FROM devices WHERE home_id IN (:homes) GROUP BY home_id")
                    .param("homes", homeIds)
                    .query(rs -> {
                        out.put(Sql.uuid(rs, "home_id"), rs.getInt("n"));
                    });
        }
        return out;
    }

    /** Completion time of the latest scan that ended with results (COMPLETED or COMPLETED_WITH_WARNINGS). */
    public Map<UUID, Instant> lastCompletedScans(Collection<UUID> homeIds) {
        Map<UUID, Instant> out = new HashMap<>();
        if (!homeIds.isEmpty()) {
            jdbc.sql("""
                    SELECT home_id, max(completed_at) AS at FROM scans
                    WHERE home_id IN (:homes) AND status IN ('COMPLETED', 'COMPLETED_WITH_WARNINGS')
                    GROUP BY home_id""")
                    .param("homes", homeIds)
                    .query(rs -> {
                        out.put(Sql.uuid(rs, "home_id"), Sql.instant(rs, "at"));
                    });
        }
        return out;
    }
}
