package com.shsc.shared.persistence;

import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Explicit switching of the tenant context. Used by request authentication (tenant taken
 * from a verified token) and by pre-authentication flows, after resolving the tenant from a
 * secret (refresh token, e-mail token, agent token) through a SECURITY DEFINER lookup.
 * The switch must happen outside a transaction: the tenant is applied when the next
 * transaction begins.
 */
@Component
public class TenantScope {

    /** Binds the tenant to the current request thread (cleared by TenantContextFilter). */
    public void enter(UUID tenantId) {
        requireNoTransaction();
        TenantContext.set(tenantId);
    }

    /** Runs {@code action} with the given tenant, restoring the previous one afterwards. */
    public <T> T callAs(UUID tenantId, Supplier<T> action) {
        requireNoTransaction();
        UUID previous = TenantContext.current().orElse(null);
        TenantContext.set(tenantId);
        try {
            return action.get();
        } finally {
            TenantContext.set(previous);
        }
    }

    public void runAs(UUID tenantId, Runnable action) {
        callAs(tenantId, () -> {
            action.run();
            return null;
        });
    }

    private static void requireNoTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("The tenant can only be switched outside a transaction");
        }
    }
}
