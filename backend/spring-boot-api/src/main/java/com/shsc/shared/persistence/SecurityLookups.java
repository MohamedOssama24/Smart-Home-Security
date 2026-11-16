package com.shsc.shared.persistence;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Pre-authentication lookups through the SECURITY DEFINER functions of migrations V002/V003.
 * They only reveal the tenant (and user id) bound to a secret or e-mail, so that the
 * caller can open a correctly scoped transaction where RLS applies to everything else.
 */
@Component
public class SecurityLookups {

    public enum SecretKind { REFRESH_TOKEN, USER_ACTION_TOKEN, AGENT_ENROLLMENT_TOKEN, AGENT_ACCESS_TOKEN }

    public record UserRef(UUID userId, UUID tenantId) {
    }

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;

    public SecurityLookups(JdbcClient jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    public Optional<UserRef> userByEmail(String email) {
        return tx.execute(status -> jdbc.sql("SELECT user_id, tenant_id FROM auth_lookup_user(CAST(:email AS citext))")
                .param("email", email)
                .query((rs, n) -> new UserRef(Sql.uuid(rs, "user_id"), Sql.uuid(rs, "tenant_id")))
                .optional());
    }

    public Optional<UUID> tenantBySecret(SecretKind kind, byte[] hash) {
        return tx.execute(status -> firstNonNull(jdbc.sql("SELECT lookup_tenant_by_secret(:kind, :hash)")
                .param("kind", kind.name())
                .param("hash", hash)
                .query(UUID.class)
                .list()));
    }

    public Optional<UUID> tenantOfAgent(UUID agentId) {
        return tx.execute(status -> firstNonNull(
                jdbc.sql("SELECT agent_lookup_tenant(:agent)").param("agent", agentId).query(UUID.class).list()));
    }

    // the functions return one row whose value is NULL when nothing matches
    private static Optional<UUID> firstNonNull(List<UUID> values) {
        return values.stream().filter(Objects::nonNull).findFirst();
    }
}
