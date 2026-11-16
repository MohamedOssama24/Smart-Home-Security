package com.shsc.shared.persistence;

import java.util.Optional;
import java.util.UUID;

/**
 * Tenant of the current unit of work. Every transaction started by
 * {@link TenantAwareTransactionManager} copies it into the PostgreSQL setting
 * {@code app.tenant_id}, which drives Row-Level Security. No tenant = no rows.
 */
public final class TenantContext {

    private static final ThreadLocal<UUID> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    public static Optional<UUID> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    static void set(UUID tenantId) {
        if (tenantId == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(tenantId);
        }
    }

    public static void clear() {
        CURRENT.remove();
    }
}
