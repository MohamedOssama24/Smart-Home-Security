package com.shsc.audit;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.persistence.Sql;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/** Read access to the audit log of the caller's tenant (RLS) — permission {@code audit:read}. */
@RestController
public class AuditController {

    public record AuditEntry(UUID id, Instant occurredAt, String actorType, UUID actorId, String action,
            String outcome, String targetType, UUID targetId, String ipAddress, Map<String, Object> details) {
    }

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final AccessPolicy access;
    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final JsonMapper json;

    public AuditController(AccessPolicy access, JdbcClient jdbc, TransactionTemplate tx, JsonMapper json) {
        this.access = access;
        this.jdbc = jdbc;
        this.tx = tx;
        this.json = json;
    }

    @GetMapping("/api/v1/audit-logs")
    public List<AuditEntry> list(@RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        access.requireTenantWide(Permissions.AUDIT_READ);
        int limit = Math.clamp(size, 1, 200);
        int offset = Math.max(0, page) * limit;
        return tx.execute(s -> jdbc.sql("""
                SELECT id, occurred_at, actor_type, actor_id, action, outcome, target_type, target_id, ip_address,
                       details::text AS details
                FROM audit_logs ORDER BY occurred_at DESC, id DESC LIMIT :limit OFFSET :offset""")
                .param("limit", limit).param("offset", offset)
                .query((rs, n) -> new AuditEntry(Sql.uuid(rs, "id"), Sql.instant(rs, "occurred_at"),
                        rs.getString("actor_type"), Sql.uuid(rs, "actor_id"), rs.getString("action"),
                        rs.getString("outcome"), rs.getString("target_type"), Sql.uuid(rs, "target_id"),
                        rs.getString("ip_address"), json.readValue(rs.getString("details"), MAP)))
                .list());
    }
}
