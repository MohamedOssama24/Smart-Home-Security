package com.shsc.alerts;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Alerts, their deliveries and the notification preferences (tenant-scoped, under RLS). */
@Repository
public class AlertRepository {

    public record NewAlert(UUID tenantId, UUID homeId, UUID deviceId, AlertType type, String severity,
            String dedupKey, String payloadJson, Instant at) {
    }

    /** {@code created} false when an unresolved alert with the same key was only repeated. */
    public record Raised(UUID id, boolean created) {
    }

    public record Recipient(UUID id, String email, String displayName, String locale) {
    }

    public record Preference(AlertType type, AlertType.Channel channel, boolean enabled, String minSeverity) {
    }

    public record InboxItem(UUID alertId, UUID homeId, String homeName, UUID deviceId, String type, String severity,
            int occurrences, Instant firstAt, Instant lastAt, Instant resolvedAt, Instant readAt, String payloadJson) {
    }

    public record DeliveryJob(UUID deliveryId, UUID tenantId, int attempts, UUID userId, UUID alertId, String email, String displayName,
            String locale, String userStatus, UUID homeId, String homeName, String type, String severity,
            int occurrences, String payloadJson) {
    }

    public record SevereFinding(UUID id, UUID deviceId, String deviceName, String deviceIp, String ruleId,
            String titleKey, String paramsJson, String severity, String type) {
    }

    public record NewDevice(UUID id, String name, String ip) {
    }

    public record SnapshotScore(Integer score, String riskLevel, Integer previousScore, Integer scoreChange,
            String previousLevel) {
    }

    public record AgentInfo(UUID id, UUID homeId, String name, Instant lastHeartbeatAt, String status) {
    }

    private final JdbcClient jdbc;

    public AlertRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    // --- alerts -------------------------------------------------------------------------------

    /** New alert, or one more occurrence of the unresolved alert with the same key (deduplication). */
    public Raised raise(NewAlert a) {
        return jdbc.sql("""
                INSERT INTO alerts (tenant_id, home_id, device_id, type, severity, dedup_key, first_at, last_at,
                    payload)
                VALUES (:tenant, :home, :device, :type, :severity, :key, :at, :at, CAST(:payload AS jsonb))
                ON CONFLICT (tenant_id, dedup_key) WHERE resolved_at IS NULL
                DO UPDATE SET occurrences = alerts.occurrences + 1, last_at = EXCLUDED.last_at,
                    severity = EXCLUDED.severity, payload = EXCLUDED.payload
                RETURNING id, (xmax = 0) AS created""")
                .param("tenant", a.tenantId()).param("home", a.homeId()).param("device", a.deviceId())
                .param("type", a.type().name()).param("severity", a.severity()).param("key", a.dedupKey())
                .param("at", Sql.ts(a.at())).param("payload", a.payloadJson())
                .query((rs, n) -> new Raised(Sql.uuid(rs, "id"), rs.getBoolean("created"))).single();
    }

    /** Ends the condition of the unresolved alert with this key; false if there is none. */
    public boolean resolve(String dedupKey, Instant now) {
        return jdbc.sql("UPDATE alerts SET resolved_at = :now WHERE dedup_key = :key AND resolved_at IS NULL")
                .param("key", dedupKey).param("now", Sql.ts(now)).update() > 0;
    }

    public Optional<UUID> findOpen(String dedupKey) {
        return jdbc.sql("SELECT id FROM alerts WHERE dedup_key = :key AND resolved_at IS NULL")
                .param("key", dedupKey).query((rs, n) -> Sql.uuid(rs, "id")).optional();
    }

    // --- recipients, preferences, deliveries ----------------------------------------------------

    /** Active users of the tenant with a verified e-mail. */
    public List<Recipient> recipients() {
        return jdbc.sql("""
                SELECT id, email, display_name, locale FROM users
                WHERE status = 'ACTIVE' AND email_verified_at IS NOT NULL ORDER BY id""")
                .query((rs, n) -> new Recipient(Sql.uuid(rs, "id"), rs.getString("email"),
                        rs.getString("display_name"), rs.getString("locale"))).list();
    }

    public List<Preference> preferences(UUID userId) {
        return jdbc.sql("""
                SELECT alert_type, channel, enabled, min_severity FROM notification_preferences
                WHERE user_id = :user""")
                .param("user", userId)
                .query((rs, n) -> new Preference(AlertType.valueOf(rs.getString("alert_type")),
                        AlertType.Channel.valueOf(rs.getString("channel")), rs.getBoolean("enabled"),
                        rs.getString("min_severity"))).list();
    }

    public void savePreference(UUID tenantId, UUID userId, Preference p, Instant now) {
        jdbc.sql("""
                INSERT INTO notification_preferences (tenant_id, user_id, alert_type, channel, enabled, min_severity,
                    updated_at)
                VALUES (:tenant, :user, :type, :channel, :enabled, :min, :now)
                ON CONFLICT (user_id, alert_type, channel)
                DO UPDATE SET enabled = EXCLUDED.enabled, min_severity = EXCLUDED.min_severity,
                    updated_at = EXCLUDED.updated_at""")
                .param("tenant", tenantId).param("user", userId).param("type", p.type().name())
                .param("channel", p.channel().name()).param("enabled", p.enabled()).param("min", p.minSeverity())
                .param("now", Sql.ts(now)).update();
    }

    public void insertDelivery(UUID tenantId, UUID alertId, UUID userId, AlertType.Channel channel, Instant now) {
        boolean queued = channel != AlertType.Channel.DASHBOARD; // e-mail and push are sent by AlertJobs
        jdbc.sql("""
                INSERT INTO alert_deliveries (tenant_id, alert_id, user_id, channel, status, next_attempt_at,
                    created_at)
                VALUES (:tenant, :alert, :user, :channel, :status, :next, :now)
                ON CONFLICT (alert_id, user_id, channel) DO NOTHING""")
                .param("tenant", tenantId).param("alert", alertId).param("user", userId)
                .param("channel", channel.name()).param("status", queued ? "PENDING" : "DELIVERED")
                .param("next", queued ? Sql.ts(now) : null).param("now", Sql.ts(now)).update();
    }

    // --- inbox --------------------------------------------------------------------------------

    public List<InboxItem> inbox(UUID userId, boolean unreadOnly, int limit) {
        return jdbc.sql("""
                SELECT a.id, a.home_id, h.name AS home_name, a.device_id, a.type, a.severity, a.occurrences,
                    a.first_at, a.last_at, a.resolved_at, d.read_at, a.payload::text AS payload
                FROM alert_deliveries d
                JOIN alerts a ON a.id = d.alert_id
                JOIN homes h ON h.id = a.home_id
                WHERE d.user_id = :user AND d.channel = 'DASHBOARD' AND (NOT :unread OR d.read_at IS NULL)
                ORDER BY a.last_at DESC, a.id DESC
                LIMIT :limit""")
                .param("user", userId).param("unread", unreadOnly).param("limit", limit)
                .query((rs, n) -> inboxItem(rs)).list();
    }

    public Optional<InboxItem> inboxItem(UUID userId, UUID alertId) {
        return jdbc.sql("""
                SELECT a.id, a.home_id, h.name AS home_name, a.device_id, a.type, a.severity, a.occurrences,
                    a.first_at, a.last_at, a.resolved_at, d.read_at, a.payload::text AS payload
                FROM alert_deliveries d
                JOIN alerts a ON a.id = d.alert_id
                JOIN homes h ON h.id = a.home_id
                WHERE d.user_id = :user AND d.channel = 'DASHBOARD' AND a.id = :alert""")
                .param("user", userId).param("alert", alertId).query((rs, n) -> inboxItem(rs)).optional();
    }

    private static InboxItem inboxItem(ResultSet rs) throws SQLException {
        return new InboxItem(Sql.uuid(rs, "id"), Sql.uuid(rs, "home_id"), rs.getString("home_name"),
                Sql.uuid(rs, "device_id"), rs.getString("type"), rs.getString("severity"), rs.getInt("occurrences"),
                Sql.instant(rs, "first_at"), Sql.instant(rs, "last_at"), Sql.instant(rs, "resolved_at"),
                Sql.instant(rs, "read_at"), rs.getString("payload"));
    }

    public void markRead(UUID userId, List<UUID> alertIds, Instant now) {
        if (alertIds.isEmpty()) {
            return;
        }
        jdbc.sql("""
                UPDATE alert_deliveries SET read_at = :now
                WHERE user_id = :user AND channel = 'DASHBOARD' AND read_at IS NULL AND alert_id IN (:ids)""")
                .param("user", userId).param("ids", alertIds).param("now", Sql.ts(now)).update();
    }

    // --- e-mail and push dispatch -------------------------------------------------------------

    /** The pending delivery of the channel, locked (skipped if another dispatcher holds it). */
    public Optional<DeliveryJob> lockDelivery(UUID deliveryId, AlertType.Channel channel) {
        return jdbc.sql("""
                SELECT d.id, d.tenant_id, d.attempts, d.user_id, d.alert_id, u.email, u.display_name, u.locale, u.status AS user_status,
                    a.home_id, h.name AS home_name, a.type, a.severity, a.occurrences, a.payload::text AS payload
                FROM alert_deliveries d
                JOIN users u ON u.id = d.user_id
                JOIN alerts a ON a.id = d.alert_id
                JOIN homes h ON h.id = a.home_id
                WHERE d.id = :id AND d.status = 'PENDING' AND d.channel = :channel
                FOR UPDATE OF d SKIP LOCKED""")
                .param("id", deliveryId).param("channel", channel.name())
                .query((rs, n) -> new DeliveryJob(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), rs.getInt("attempts"),
                        Sql.uuid(rs, "user_id"), Sql.uuid(rs, "alert_id"), rs.getString("email"), rs.getString("display_name"), rs.getString("locale"),
                        rs.getString("user_status"), Sql.uuid(rs, "home_id"), rs.getString("home_name"),
                        rs.getString("type"), rs.getString("severity"), rs.getInt("occurrences"),
                        rs.getString("payload"))).optional();
    }

    public void deliverySent(UUID deliveryId, int attempts, Instant now) {
        jdbc.sql("""
                UPDATE alert_deliveries SET status = 'SENT', attempts = :attempts, sent_at = :now,
                    next_attempt_at = NULL, error = NULL WHERE id = :id""")
                .param("id", deliveryId).param("attempts", attempts).param("now", Sql.ts(now)).update();
    }

    /** Retried at {@code next}, or FAILED when {@code next} is null. */
    public void deliveryNotSent(UUID deliveryId, int attempts, String error, Instant next) {
        jdbc.sql("""
                UPDATE alert_deliveries SET status = CASE WHEN CAST(:next AS timestamptz) IS NULL THEN 'FAILED'
                    ELSE 'PENDING' END, attempts = :attempts, error = :error, next_attempt_at = :next
                WHERE id = :id""")
                .param("id", deliveryId).param("attempts", attempts).param("error", error)
                .param("next", next == null ? null : Sql.ts(next)).update();
    }

    // --- facts the alerts are built from ------------------------------------------------------

    /** Open HIGH / CRITICAL findings the scan detected (new or seen again). */
    public List<SevereFinding> severeFindingsSeen(UUID homeId, UUID scanId) {
        return jdbc.sql("""
                SELECT f.id, f.device_id, coalesce(d.hostname, host(d.current_ip)) AS device_name,
                    host(d.current_ip) AS device_ip, f.rule_id, f.title_key, f.params::text AS params, f.severity,
                    f.finding_type
                FROM findings f JOIN devices d ON d.id = f.device_id
                WHERE f.home_id = :home AND f.last_scan_id = :scan AND f.status = 'OPEN'
                  AND f.severity IN ('HIGH', 'CRITICAL')
                ORDER BY f.id""")
                .param("home", homeId).param("scan", scanId).query((rs, n) -> severe(rs)).list();
    }

    /** Findings the analysis of this scan resolved (resolved_at is the completion instant). */
    public List<SevereFinding> resolvedAt(UUID homeId, Instant now) {
        return jdbc.sql("""
                SELECT f.id, f.device_id, coalesce(d.hostname, host(d.current_ip)) AS device_name,
                    host(d.current_ip) AS device_ip, f.rule_id, f.title_key, f.params::text AS params, f.severity,
                    f.finding_type
                FROM findings f JOIN devices d ON d.id = f.device_id
                WHERE f.home_id = :home AND f.status = 'RESOLVED' AND f.resolved_at = :now
                ORDER BY f.id""")
                .param("home", homeId).param("now", Sql.ts(now)).query((rs, n) -> severe(rs)).list();
    }

    private static SevereFinding severe(ResultSet rs) throws SQLException {
        return new SevereFinding(Sql.uuid(rs, "id"), Sql.uuid(rs, "device_id"), rs.getString("device_name"),
                rs.getString("device_ip"), rs.getString("rule_id"), rs.getString("title_key"),
                rs.getString("params"), rs.getString("severity"), rs.getString("finding_type"));
    }

    /** Devices first seen by this scan. */
    public List<NewDevice> devicesFirstSeen(UUID homeId, UUID scanId) {
        return jdbc.sql("""
                SELECT id, coalesce(hostname, host(current_ip)) AS name, host(current_ip) AS ip FROM devices
                WHERE home_id = :home AND first_scan_id = :scan ORDER BY current_ip""")
                .param("home", homeId).param("scan", scanId)
                .query((rs, n) -> new NewDevice(Sql.uuid(rs, "id"), rs.getString("name"), rs.getString("ip"))).list();
    }

    /** True when another scan of the home completed before this one (the first scan is the baseline). */
    public boolean completedBefore(UUID homeId, UUID scanId) {
        return jdbc.sql("""
                SELECT EXISTS (SELECT 1 FROM scans WHERE home_id = :home AND id <> :scan
                    AND status IN ('COMPLETED', 'COMPLETED_WITH_WARNINGS'))""")
                .param("home", homeId).param("scan", scanId).query(Boolean.class).single();
    }

    public Optional<SnapshotScore> snapshotScore(UUID snapshotId) {
        return jdbc.sql("""
                SELECT s.score, s.risk_level, (s.delta_from_previous ->> 'previousScore')::int AS previous_score,
                    (s.delta_from_previous ->> 'scoreChange')::int AS score_change, p.risk_level AS previous_level
                FROM risk_snapshots s
                LEFT JOIN risk_snapshots p ON p.id = (s.delta_from_previous ->> 'previousSnapshotId')::uuid
                WHERE s.id = :id""")
                .param("id", snapshotId)
                .query((rs, n) -> new SnapshotScore((Integer) rs.getObject("score"), rs.getString("risk_level"),
                        (Integer) rs.getObject("previous_score"), (Integer) rs.getObject("score_change"),
                        rs.getString("previous_level"))).optional();
    }

    public Optional<AgentInfo> agent(UUID agentId) {
        return jdbc.sql("SELECT id, home_id, name, last_heartbeat_at, status FROM agents WHERE id = :id")
                .param("id", agentId)
                .query((rs, n) -> new AgentInfo(Sql.uuid(rs, "id"), Sql.uuid(rs, "home_id"), rs.getString("name"),
                        Sql.instant(rs, "last_heartbeat_at"), rs.getString("status"))).optional();
    }
}
