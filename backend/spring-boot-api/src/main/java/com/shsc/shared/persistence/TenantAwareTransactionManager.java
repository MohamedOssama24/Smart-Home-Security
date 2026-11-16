package com.shsc.shared.persistence;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.transaction.TransactionDefinition;

/**
 * Sets {@code app.tenant_id} (transaction-local) at the beginning of every transaction,
 * from {@link TenantContext}. Combined with RLS policies and a runtime DB role without
 * BYPASSRLS this is the database half of tenant isolation (ADR-004).
 */
public class TenantAwareTransactionManager extends JdbcTransactionManager {

    private static final String SET_TENANT = "SELECT set_config('app.tenant_id', ?, true)";

    public TenantAwareTransactionManager(DataSource dataSource) {
        super(dataSource);
    }

    @Override
    protected void prepareTransactionalConnection(Connection con, TransactionDefinition definition)
            throws SQLException {
        super.prepareTransactionalConnection(con, definition);
        try (PreparedStatement statement = con.prepareStatement(SET_TENANT)) {
            statement.setString(1, TenantContext.current().map(Object::toString).orElse(""));
            statement.execute();
        }
    }
}
