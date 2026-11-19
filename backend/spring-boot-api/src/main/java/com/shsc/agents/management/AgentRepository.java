package com.shsc.agents.management;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Agents, their credentials, access tokens and enrollment tokens (RLS: current tenant). */
@Repository
public class AgentRepository {

    public enum AgentStatus { ACTIVE, REVOKED }

    /** An agent; capabilities and interfaces are the JSON last reported by its heartbeat. */
    public record Agent(UUID id, UUID homeId, String name, String hostname, String os, String arch,
            String agentVersion, AgentStatus status, Instant enrolledAt, Instant lastSeenAt, Instant revokedAt,
            String revokeReason, Instant lastHeartbeatAt, String capabilitiesJson, String interfacesJson,
            Integer queueDepth, Long uptimeSeconds, String lastError) {
    }

    /** Self-diagnosis reported by a heartbeat; interfacesJson null = unchanged since the last one. */
    public record Heartbeat(String agentVersion, long uptimeSeconds, String interfacesHash, String interfacesJson,
            String capabilitiesJson, int queueDepth, String lastError) {
    }

    public record AgentEvent(UUID eventId, String type, Instant occurredAt, Instant receivedAt, String detailJson) {
    }

    public record Credential(UUID id, UUID agentId, byte[] publicKey, String status, Instant createdAt) {
    }

    public record EnrollmentToken(UUID id, UUID homeId, UUID createdBy, Instant createdAt, Instant expiresAt,
            Instant usedAt, UUID usedByAgentId, Instant revokedAt) {

        public String state(Instant now) {
            if (revokedAt != null) {
                return "REVOKED";
            }
            if (usedAt != null) {
                return "USED";
            }
            return expiresAt.isAfter(now) ? "ACTIVE" : "EXPIRED";
        }
    }

    public record AccessTokenRow(UUID id, UUID agentId, UUID credentialId, Instant expiresAt) {
    }

    private static final String AGENT_COLUMNS = """
            id, home_id, name, hostname, os, arch, agent_version, status, enrolled_at, last_seen_at, revoked_at,
            revoke_reason, last_heartbeat_at, capabilities::text AS capabilities, interfaces::text AS interfaces,
            queue_depth, uptime_seconds, last_error""";
    private static final String TOKEN_COLUMNS =
            "id, home_id, created_by, created_at, expires_at, used_at, used_by_agent_id, revoked_at";

    private final JdbcClient jdbc;

    public AgentRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    // --------------------------------------------------------------- enrollment tokens

    public EnrollmentToken insertEnrollmentToken(UUID tenantId, UUID homeId, byte[] hash, UUID createdBy,
            Instant now, Instant expiresAt) {
        return jdbc.sql("""
                INSERT INTO agent_enrollment_tokens (tenant_id, home_id, token_hash, created_by, created_at, expires_at)
                VALUES (:tenant, :home, :hash, :by, :now, :expires)
                RETURNING """ + " " + TOKEN_COLUMNS)
                .param("tenant", tenantId).param("home", homeId).param("hash", hash).param("by", createdBy)
                .param("now", Sql.ts(now)).param("expires", Sql.ts(expiresAt))
                .query(AgentRepository::mapToken).single();
    }

    public List<EnrollmentToken> enrollmentTokens(UUID homeId) {
        return jdbc.sql("SELECT " + TOKEN_COLUMNS + " FROM agent_enrollment_tokens WHERE home_id = :home ORDER BY created_at DESC LIMIT 50")
                .param("home", homeId).query(AgentRepository::mapToken).list();
    }

    public Optional<EnrollmentToken> lockEnrollmentToken(UUID id) {
        return jdbc.sql("SELECT " + TOKEN_COLUMNS + " FROM agent_enrollment_tokens WHERE id = :id FOR UPDATE")
                .param("id", id).query(AgentRepository::mapToken).optional();
    }

    public Optional<EnrollmentToken> lockEnrollmentTokenByHash(byte[] hash) {
        return jdbc.sql("SELECT " + TOKEN_COLUMNS + " FROM agent_enrollment_tokens WHERE token_hash = :hash FOR UPDATE")
                .param("hash", hash).query(AgentRepository::mapToken).optional();
    }

    public void revokeEnrollmentToken(UUID id, UUID by, Instant now) {
        jdbc.sql("UPDATE agent_enrollment_tokens SET revoked_at = :now, revoked_by = :by WHERE id = :id AND revoked_at IS NULL")
                .param("id", id).param("by", by).param("now", Sql.ts(now)).update();
    }

    public void markEnrollmentTokenUsed(UUID id, UUID agentId, Instant now) {
        jdbc.sql("UPDATE agent_enrollment_tokens SET used_at = :now, used_by_agent_id = :agent WHERE id = :id")
                .param("id", id).param("agent", agentId).param("now", Sql.ts(now)).update();
    }

    // --------------------------------------------------------------- agents

    public UUID insertAgent(UUID tenantId, UUID homeId, String name, String hostname, String os, String arch,
            String version, Instant now) {
        return jdbc.sql("""
                INSERT INTO agents (tenant_id, home_id, name, hostname, os, arch, agent_version, enrolled_at,
                    last_seen_at, created_at, updated_at)
                VALUES (:tenant, :home, :name, :hostname, :os, :arch, :version, :now, :now, :now, :now)
                RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).param("name", name).param("hostname", hostname)
                .param("os", os).param("arch", arch).param("version", version).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public Optional<Agent> find(UUID id) {
        return jdbc.sql("SELECT " + AGENT_COLUMNS + " FROM agents WHERE id = :id")
                .param("id", id).query(AgentRepository::mapAgent).optional();
    }

    public Optional<Agent> lock(UUID id) {
        return jdbc.sql("SELECT " + AGENT_COLUMNS + " FROM agents WHERE id = :id FOR UPDATE")
                .param("id", id).query(AgentRepository::mapAgent).optional();
    }

    public List<Agent> forHome(UUID homeId) {
        return jdbc.sql("SELECT " + AGENT_COLUMNS + " FROM agents WHERE home_id = :home ORDER BY enrolled_at DESC")
                .param("home", homeId).query(AgentRepository::mapAgent).list();
    }

    public void touch(UUID id, Instant now) {
        jdbc.sql("UPDATE agents SET last_seen_at = :now WHERE id = :id")
                .param("id", id).param("now", Sql.ts(now)).update();
    }

    /** Stores a heartbeat. The interface list is replaced only when the agent sent it. */
    public void recordHeartbeat(UUID id, Heartbeat hb, Instant now) {
        jdbc.sql("""
                UPDATE agents SET last_heartbeat_at = :now, last_seen_at = :now, agent_version = :version,
                    capabilities = CAST(:capabilities AS jsonb),
                    interfaces = COALESCE(CAST(:interfaces AS jsonb), interfaces),
                    interfaces_hash = CASE WHEN CAST(:interfaces AS jsonb) IS NULL THEN interfaces_hash ELSE :hash END,
                    queue_depth = :depth, uptime_seconds = :uptime, last_error = :error
                WHERE id = :id AND status = 'ACTIVE'""")
                .param("id", id).param("now", Sql.ts(now)).param("version", hb.agentVersion())
                .param("capabilities", hb.capabilitiesJson()).param("interfaces", hb.interfacesJson())
                .param("hash", hb.interfacesHash()).param("depth", hb.queueDepth()).param("uptime", hb.uptimeSeconds())
                .param("error", hb.lastError()).update();
    }

    /** Inserts an event unless already received (idempotent); returns true if new. */
    public boolean insertEvent(UUID tenantId, UUID agentId, UUID eventId, String type, Instant occurredAt,
            String detailJson, Instant now) {
        return jdbc.sql("""
                INSERT INTO agent_events (tenant_id, agent_id, event_id, type, occurred_at, received_at, detail)
                VALUES (:tenant, :agent, :event, :type, :occurred, :now, CAST(:detail AS jsonb))
                ON CONFLICT (agent_id, event_id) DO NOTHING""")
                .param("tenant", tenantId).param("agent", agentId).param("event", eventId).param("type", type)
                .param("occurred", Sql.ts(occurredAt)).param("now", Sql.ts(now)).param("detail", detailJson)
                .update() == 1;
    }

    /** Keeps only the most recent {@code keep} events of the agent. */
    public void trimEvents(UUID agentId, int keep) {
        jdbc.sql("""
                DELETE FROM agent_events WHERE agent_id = :agent AND id NOT IN (
                    SELECT id FROM agent_events WHERE agent_id = :agent ORDER BY occurred_at DESC, id DESC LIMIT :keep)""")
                .param("agent", agentId).param("keep", keep).update();
    }

    public List<AgentEvent> events(UUID agentId, int limit) {
        return jdbc.sql("""
                SELECT event_id, type, occurred_at, received_at, detail::text AS detail FROM agent_events
                WHERE agent_id = :agent ORDER BY occurred_at DESC, id DESC LIMIT :limit""")
                .param("agent", agentId).param("limit", limit)
                .query((rs, n) -> new AgentEvent(Sql.uuid(rs, "event_id"), rs.getString("type"),
                        Sql.instant(rs, "occurred_at"), Sql.instant(rs, "received_at"), rs.getString("detail")))
                .list();
    }

    public void revokeAgent(UUID id, UUID by, String reason, Instant now) {
        jdbc.sql("""
                UPDATE agents SET status = 'REVOKED', revoked_at = :now, revoked_by = :by, revoke_reason = :reason,
                    updated_at = :now WHERE id = :id AND status = 'ACTIVE'""")
                .param("id", id).param("by", by).param("reason", reason).param("now", Sql.ts(now)).update();
        jdbc.sql("UPDATE agent_credentials SET status = 'REVOKED', retired_at = :now WHERE agent_id = :id AND status = 'ACTIVE'")
                .param("id", id).param("now", Sql.ts(now)).update();
        revokeAccessTokens(id, now);
    }

    // --------------------------------------------------------------- credentials

    public UUID insertCredential(UUID tenantId, UUID agentId, byte[] publicKey, Instant now) {
        return jdbc.sql("""
                INSERT INTO agent_credentials (tenant_id, agent_id, public_key, created_at)
                VALUES (:tenant, :agent, :key, :now) RETURNING id""")
                .param("tenant", tenantId).param("agent", agentId).param("key", publicKey).param("now", Sql.ts(now))
                .query(UUID.class).single();
    }

    public Optional<Credential> activeCredential(UUID agentId) {
        return jdbc.sql("""
                SELECT id, agent_id, public_key, status, created_at FROM agent_credentials
                WHERE agent_id = :agent AND status = 'ACTIVE' FOR UPDATE""")
                .param("agent", agentId)
                .query((rs, n) -> new Credential(Sql.uuid(rs, "id"), Sql.uuid(rs, "agent_id"), rs.getBytes("public_key"),
                        rs.getString("status"), Sql.instant(rs, "created_at")))
                .optional();
    }

    public void retireCredential(UUID credentialId, Instant now) {
        jdbc.sql("UPDATE agent_credentials SET status = 'ROTATED', retired_at = :now WHERE id = :id AND status = 'ACTIVE'")
                .param("id", credentialId).param("now", Sql.ts(now)).update();
    }

    // --------------------------------------------------------------- anti-replay and access tokens

    /** Returns false if the jti was already used by this agent (replay). */
    public boolean rememberAssertion(UUID tenantId, UUID agentId, String jti, Instant expiresAt) {
        int inserted = jdbc.sql("""
                INSERT INTO agent_assertion_jti (agent_id, jti, tenant_id, expires_at)
                VALUES (:agent, :jti, :tenant, :expires) ON CONFLICT DO NOTHING""")
                .param("agent", agentId).param("jti", jti).param("tenant", tenantId)
                .param("expires", Sql.ts(expiresAt)).update();
        return inserted == 1;
    }

    public void insertAccessToken(UUID tenantId, UUID agentId, UUID credentialId, byte[] hash, Instant now,
            Instant expiresAt) {
        jdbc.sql("""
                INSERT INTO agent_access_tokens (tenant_id, agent_id, credential_id, token_hash, created_at, expires_at)
                VALUES (:tenant, :agent, :credential, :hash, :now, :expires)""")
                .param("tenant", tenantId).param("agent", agentId).param("credential", credentialId)
                .param("hash", hash).param("now", Sql.ts(now)).param("expires", Sql.ts(expiresAt)).update();
    }

    /** A token is valid only while it, its credential and its agent are all active. */
    public Optional<AccessTokenRow> findValidAccessToken(byte[] hash, Instant now) {
        return jdbc.sql("""
                SELECT t.id, t.agent_id, t.credential_id, t.expires_at
                FROM agent_access_tokens t
                JOIN agent_credentials c ON c.id = t.credential_id
                JOIN agents a ON a.id = t.agent_id
                WHERE t.token_hash = :hash AND t.revoked_at IS NULL AND t.expires_at > :now
                  AND c.status = 'ACTIVE' AND a.status = 'ACTIVE'""")
                .param("hash", hash).param("now", Sql.ts(now))
                .query((rs, n) -> new AccessTokenRow(Sql.uuid(rs, "id"), Sql.uuid(rs, "agent_id"),
                        Sql.uuid(rs, "credential_id"), Sql.instant(rs, "expires_at")))
                .optional();
    }

    public Optional<UUID> agentOfAccessToken(byte[] hash) {
        return jdbc.sql("SELECT agent_id FROM agent_access_tokens WHERE token_hash = :hash")
                .param("hash", hash).query(UUID.class).optional();
    }

    public void revokeAccessTokens(UUID agentId, Instant now) {
        jdbc.sql("UPDATE agent_access_tokens SET revoked_at = :now WHERE agent_id = :agent AND revoked_at IS NULL")
                .param("agent", agentId).param("now", Sql.ts(now)).update();
    }

    private static Agent mapAgent(ResultSet rs, int row) throws SQLException {
        return new Agent(Sql.uuid(rs, "id"), Sql.uuid(rs, "home_id"), rs.getString("name"), rs.getString("hostname"),
                rs.getString("os"), rs.getString("arch"), rs.getString("agent_version"),
                AgentStatus.valueOf(rs.getString("status")), Sql.instant(rs, "enrolled_at"),
                Sql.instant(rs, "last_seen_at"), Sql.instant(rs, "revoked_at"), rs.getString("revoke_reason"),
                Sql.instant(rs, "last_heartbeat_at"), rs.getString("capabilities"), rs.getString("interfaces"),
                rs.getObject("queue_depth", Integer.class), rs.getObject("uptime_seconds", Long.class),
                rs.getString("last_error"));
    }

    private static EnrollmentToken mapToken(ResultSet rs, int row) throws SQLException {
        return new EnrollmentToken(Sql.uuid(rs, "id"), Sql.uuid(rs, "home_id"), Sql.uuid(rs, "created_by"),
                Sql.instant(rs, "created_at"), Sql.instant(rs, "expires_at"), Sql.instant(rs, "used_at"),
                Sql.uuid(rs, "used_by_agent_id"), Sql.instant(rs, "revoked_at"));
    }
}
