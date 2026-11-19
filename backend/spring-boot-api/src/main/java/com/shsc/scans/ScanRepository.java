package com.shsc.scans;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Scans, their targets, transition history, uploaded batches and observations (RLS: current tenant). */
@Repository
public class ScanRepository {

    public enum Status {
        PENDING, QUEUED, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED;

        public boolean terminal() {
            return this == COMPLETED || this == COMPLETED_WITH_WARNINGS || this == FAILED || this == CANCELLED;
        }
    }

    public enum ActorType { USER, AGENT, SYSTEM }

    public record Scan(UUID id, UUID tenantId, UUID homeId, UUID agentId, String trigger, String profile,
            Status status, UUID requestedBy, Instant requestedAt, Instant queuedAt, Instant jobExpiresAt,
            Instant startedAt, Instant leaseExpiresAt, Instant deadlineAt, Instant completedAt,
            Instant cancelRequestedAt, String progressJson, int devicesDiscovered, int outOfScopeDropped,
            Integer totalBatches, String warningsJson, String failureReason, int version) {
    }

    public record Target(UUID networkId, String cidr) {
    }

    public record ScanEvent(String fromStatus, String toStatus, ActorType actorType, UUID actorId, String reason,
            Instant at) {
    }

    /** details: JSON object (method-specific, self-declared data is marked as such), or null. */
    public record Observation(String ip, String mac, String method, String iface, String hostname, String details,
            Instant observedAt) {
    }

    /** Fields changed by a transition; null = unchanged. */
    public record Changes(Instant queuedAt, Instant jobExpiresAt, Instant startedAt, Instant leaseExpiresAt,
            Instant deadlineAt, Instant completedAt, String failureReason, String warningsJson) {

        public static Changes none() {
            return new Changes(null, null, null, null, null, null, null, null);
        }
    }

    private static final String COLUMNS = """
            id, tenant_id, home_id, agent_id, trigger, profile, status, requested_by, requested_at, queued_at,
            job_expires_at, started_at, lease_expires_at, deadline_at, completed_at, cancel_requested_at,
            progress::text AS progress, devices_discovered, out_of_scope_dropped, total_batches,
            warnings::text AS warnings, failure_reason, version""";

    private final JdbcClient jdbc;

    public ScanRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(UUID tenantId, UUID homeId, UUID agentId, String profile, UUID requestedBy,
            String idempotencyKey, Instant now) {
        return jdbc.sql("""
                INSERT INTO scans (tenant_id, home_id, agent_id, profile, status, requested_by, requested_at,
                    idempotency_key)
                VALUES (:tenant, :home, :agent, :profile, 'PENDING', :by, :now, :key) RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("agent", agentId).param("profile", profile)
                .param("by", requestedBy).param("now", Sql.ts(now)).param("key", idempotencyKey)
                .query(UUID.class).single();
    }

    public void insertTarget(UUID tenantId, UUID scanId, UUID networkId, String cidr) {
        jdbc.sql("""
                INSERT INTO scan_targets (tenant_id, scan_id, network_id, cidr)
                VALUES (:tenant, :scan, :network, CAST(:cidr AS cidr))""")
                .param("tenant", tenantId).param("scan", scanId).param("network", networkId).param("cidr", cidr)
                .update();
    }

    public Optional<Scan> find(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE id = :id")
                .param("id", id).query(ScanRepository::map).optional();
    }

    public Optional<Scan> lock(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE id = :id FOR UPDATE")
                .param("id", id).query(ScanRepository::map).optional();
    }

    public Optional<Scan> findByIdempotencyKey(UUID requestedBy, String key) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE requested_by = :by AND idempotency_key = :key")
                .param("by", requestedBy).param("key", key).query(ScanRepository::map).optional();
    }

    public Optional<Scan> activeOfHome(UUID homeId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE home_id = :home AND status IN ('PENDING', 'QUEUED', 'RUNNING')")
                .param("home", homeId).query(ScanRepository::map).optional();
    }

    public List<Scan> forHome(UUID homeId, int limit) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE home_id = :home ORDER BY requested_at DESC LIMIT :limit")
                .param("home", homeId).param("limit", limit).query(ScanRepository::map).list();
    }

    public List<Scan> activeOfAgent(UUID agentId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM scans WHERE agent_id = :agent AND status IN ('PENDING', 'QUEUED', 'RUNNING') FOR UPDATE")
                .param("agent", agentId).query(ScanRepository::map).list();
    }

    /** Oldest queued job of the agent that has not expired yet. */
    public Optional<Scan> nextQueued(UUID agentId, Instant now) {
        return jdbc.sql("SELECT " + COLUMNS + """
                 FROM scans WHERE agent_id = :agent AND status = 'QUEUED' AND job_expires_at > :now
                ORDER BY queued_at LIMIT 1""")
                .param("agent", agentId).param("now", Sql.ts(now)).query(ScanRepository::map).optional();
    }

    /** Scans of the home requested in the last 24 hours (plan limit). */
    public int countRequestedSince(UUID homeId, Instant since) {
        return jdbc.sql("SELECT count(*) FROM scans WHERE home_id = :home AND requested_at > :since")
                .param("home", homeId).param("since", Sql.ts(since)).query(Integer.class).single();
    }

    public List<Target> targets(UUID scanId) {
        return jdbc.sql("SELECT network_id, cidr::text AS cidr FROM scan_targets WHERE scan_id = :scan ORDER BY cidr")
                .param("scan", scanId)
                .query((rs, n) -> new Target(Sql.uuid(rs, "network_id"), rs.getString("cidr"))).list();
    }

    /**
     * Applies a transition with optimistic locking; returns false if the scan changed in the
     * meantime (different version), in which case nothing is written.
     */
    public boolean transition(Scan scan, Status to, Changes changes, Instant now) {
        return jdbc.sql("""
                UPDATE scans SET status = :to, version = version + 1,
                    queued_at = COALESCE(:queued, queued_at), job_expires_at = COALESCE(:jobExpires, job_expires_at),
                    started_at = COALESCE(:started, started_at),
                    lease_expires_at = COALESCE(:lease, lease_expires_at),
                    deadline_at = COALESCE(:deadline, deadline_at),
                    completed_at = CASE WHEN :terminal THEN :now ELSE NULL END,
                    failure_reason = CASE WHEN :to = 'FAILED' THEN :reason ELSE NULL END,
                    warnings = COALESCE(CAST(:warnings AS jsonb), warnings)
                WHERE id = :id AND version = :version""")
                .param("id", scan.id()).param("version", scan.version()).param("to", to.name())
                .param("terminal", to.terminal()).param("now", Sql.ts(now))
                .param("queued", Sql.ts(changes.queuedAt())).param("jobExpires", Sql.ts(changes.jobExpiresAt()))
                .param("started", Sql.ts(changes.startedAt())).param("lease", Sql.ts(changes.leaseExpiresAt()))
                .param("deadline", Sql.ts(changes.deadlineAt())).param("reason", changes.failureReason())
                .param("warnings", changes.warningsJson())
                .update() == 1;
    }

    public void insertEvent(UUID tenantId, UUID scanId, Status from, Status to, ActorType actorType, UUID actorId,
            String reason, Instant at) {
        jdbc.sql("""
                INSERT INTO scan_events (tenant_id, scan_id, from_status, to_status, actor_type, actor_id, reason, at)
                VALUES (:tenant, :scan, :from, :to, :actorType, :actor, :reason, :at)""")
                .param("tenant", tenantId).param("scan", scanId).param("from", from == null ? null : from.name())
                .param("to", to.name()).param("actorType", actorType.name()).param("actor", actorId)
                .param("reason", reason).param("at", Sql.ts(at)).update();
    }

    public List<ScanEvent> events(UUID scanId) {
        return jdbc.sql("""
                SELECT from_status, to_status, actor_type, actor_id, reason, at FROM scan_events
                WHERE scan_id = :scan ORDER BY at, id""")
                .param("scan", scanId)
                .query((rs, n) -> new ScanEvent(rs.getString("from_status"), rs.getString("to_status"),
                        ActorType.valueOf(rs.getString("actor_type")), Sql.uuid(rs, "actor_id"),
                        rs.getString("reason"), Sql.instant(rs, "at")))
                .list();
    }

    public void requestCancel(UUID scanId, UUID by, Instant now) {
        jdbc.sql("""
                UPDATE scans SET cancel_requested_at = :now, cancel_requested_by = :by, version = version + 1
                WHERE id = :id AND cancel_requested_at IS NULL""")
                .param("id", scanId).param("by", by).param("now", Sql.ts(now)).update();
    }

    /** Progress report of the running scan: renews the lease. */
    public void recordProgress(UUID scanId, String progressJson, int devicesDiscovered, Instant leaseExpiresAt) {
        jdbc.sql("""
                UPDATE scans SET progress = CAST(:progress AS jsonb), lease_expires_at = :lease,
                    devices_discovered = GREATEST(devices_discovered, :devices)
                WHERE id = :id""")
                .param("id", scanId).param("progress", progressJson).param("lease", Sql.ts(leaseExpiresAt))
                .param("devices", devicesDiscovered).update();
    }

    /** Records an uploaded batch; returns false if this batch number was already received. */
    public boolean insertBatch(UUID tenantId, UUID scanId, int batchSeq, String sha256, int observations, int ports,
            int dropped, boolean late, Instant now) {
        return jdbc.sql("""
                INSERT INTO scan_result_batches (tenant_id, scan_id, batch_seq, received_at, payload_sha256,
                    observation_count, port_count, dropped_count, late)
                VALUES (:tenant, :scan, :seq, :now, :sha, :count, :ports, :dropped, :late)
                ON CONFLICT (scan_id, batch_seq) DO NOTHING""")
                .param("tenant", tenantId).param("scan", scanId).param("seq", batchSeq).param("now", Sql.ts(now))
                .param("sha", sha256).param("count", observations).param("ports", ports).param("dropped", dropped).param("late", late)
                .update() == 1;
    }

    public List<Integer> batchNumbers(UUID scanId) {
        return jdbc.sql("SELECT batch_seq FROM scan_result_batches WHERE scan_id = :scan ORDER BY batch_seq")
                .param("scan", scanId).query(Integer.class).list();
    }

    public void insertObservation(UUID tenantId, UUID scanId, Observation o) {
        jdbc.sql("""
                INSERT INTO scan_observations (tenant_id, scan_id, ip, mac, method, interface, hostname, details,
                    observed_at)
                VALUES (:tenant, :scan, CAST(:ip AS inet), CAST(:mac AS macaddr), :method, :iface, :hostname,
                    CAST(:details AS jsonb), :at)
                ON CONFLICT (scan_id, ip, method) DO UPDATE SET
                    mac = COALESCE(EXCLUDED.mac, scan_observations.mac),
                    hostname = COALESCE(EXCLUDED.hostname, scan_observations.hostname),
                    details = COALESCE(EXCLUDED.details, scan_observations.details),
                    observed_at = GREATEST(EXCLUDED.observed_at, scan_observations.observed_at)""")
                .param("tenant", tenantId).param("scan", scanId).param("ip", o.ip()).param("mac", o.mac())
                .param("method", o.method()).param("iface", o.iface()).param("hostname", o.hostname())
                .param("details", o.details()).param("at", Sql.ts(o.observedAt())).update();
    }

    /** Distinct addresses observed in the scan, refreshed after every batch. */
    public void refreshCounters(UUID scanId, int droppedNow) {
        jdbc.sql("""
                UPDATE scans SET devices_discovered = (SELECT count(DISTINCT ip) FROM scan_observations WHERE scan_id = :id),
                    out_of_scope_dropped = out_of_scope_dropped + :dropped
                WHERE id = :id""")
                .param("id", scanId).param("dropped", droppedNow).update();
    }

    public void setTotalBatches(UUID scanId, int totalBatches) {
        jdbc.sql("UPDATE scans SET total_batches = :total WHERE id = :id")
                .param("id", scanId).param("total", totalBatches).update();
    }

    public List<Observation> observations(UUID scanId) {
        return jdbc.sql("""
                SELECT host(ip) AS ip, mac::text AS mac, method, interface, hostname, details::text AS details,
                    observed_at
                FROM scan_observations WHERE scan_id = :scan ORDER BY ip, method""")
                .param("scan", scanId)
                .query((rs, n) -> new Observation(rs.getString("ip"), rs.getString("mac"), rs.getString("method"),
                        rs.getString("interface"), rs.getString("hostname"), rs.getString("details"),
                        Sql.instant(rs, "observed_at")))
                .list();
    }

    private static Scan map(ResultSet rs, int row) throws SQLException {
        return new Scan(Sql.uuid(rs, "id"), Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "home_id"),
                Sql.uuid(rs, "agent_id"), rs.getString("trigger"), rs.getString("profile"),
                Status.valueOf(rs.getString("status")), Sql.uuid(rs, "requested_by"), Sql.instant(rs, "requested_at"),
                Sql.instant(rs, "queued_at"), Sql.instant(rs, "job_expires_at"), Sql.instant(rs, "started_at"),
                Sql.instant(rs, "lease_expires_at"), Sql.instant(rs, "deadline_at"), Sql.instant(rs, "completed_at"),
                Sql.instant(rs, "cancel_requested_at"), rs.getString("progress"), rs.getInt("devices_discovered"),
                rs.getInt("out_of_scope_dropped"), rs.getObject("total_batches", Integer.class),
                rs.getString("warnings"), rs.getString("failure_reason"), rs.getInt("version"));
    }
}
