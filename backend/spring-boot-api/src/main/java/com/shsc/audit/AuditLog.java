package com.shsc.audit;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.shared.persistence.TenantContext;
import com.shsc.shared.persistence.TenantScope;

import tools.jackson.databind.json.JsonMapper;

/**
 * Append-only audit trail. Inside a business transaction the event joins it (it is committed
 * atomically with the change it describes); outside, it is written in its own transaction, so
 * rejected operations (always audited outside the rolled-back transaction) are recorded too.
 * The tenant of the event must equal
 * the tenant bound to the thread (or be null for platform/anonymous events): RLS enforces it.
 */
@Service
public class AuditLog {

    private static final Logger LOG = LoggerFactory.getLogger(AuditLog.class);

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final JsonMapper json;
    private final TenantScope tenantScope;

    public AuditLog(JdbcClient jdbc, PlatformTransactionManager transactionManager, JsonMapper json,
            TenantScope tenantScope) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactionManager);
        this.json = json;
        this.tenantScope = tenantScope;
    }

    public void record(AuditEvent event) {
        UUID bound = TenantContext.current().orElse(null);
        if (event.tenantId() != null && !event.tenantId().equals(bound)) {
            // Event about another tenant than the bound one (e.g. registration before binding):
            // write it under the event's tenant. Only possible outside a transaction.
            tenantScope.runAs(event.tenantId(), () -> insert(event));
            return;
        }
        insert(event);
    }

    private void insert(AuditEvent event) {
        try {
            tx.executeWithoutResult(status -> jdbc.sql("""
                    INSERT INTO audit_logs (tenant_id, actor_type, actor_id, action, outcome, target_type,
                        target_id, ip_address, user_agent, details)
                    VALUES (:tenant, :actorType, :actorId, :action, :outcome, :targetType, :targetId,
                        :ip, :userAgent, CAST(:details AS jsonb))
                    """)
                    .param("tenant", event.tenantId())
                    .param("actorType", event.actorType().name())
                    .param("actorId", event.actorId())
                    .param("action", event.action().name())
                    .param("outcome", event.outcome().name())
                    .param("targetType", event.targetType())
                    .param("targetId", event.targetId())
                    .param("ip", event.client() == null ? null : event.client().ip())
                    .param("userAgent", event.client() == null ? null : event.client().userAgent())
                    .param("details", json.writeValueAsString(event.details()))
                    .update());
        } catch (RuntimeException e) {
            // Audit failures must be visible to operators but must not hide the original outcome.
            LOG.error("Could not write audit event {} ({})", event.action(), event.outcome(), e);
            throw e;
        }
    }
}
