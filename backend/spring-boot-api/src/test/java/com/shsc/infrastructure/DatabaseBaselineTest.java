package com.shsc.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.support.IntegrationTest;
import com.shsc.support.PostgresTestContainer;

/**
 * Verifies the database foundation of ADR-004: migrations applied by the owner role,
 * runtime role restricted (no superuser, no BYPASSRLS, no DDL) and tenant context function.
 */
class DatabaseBaselineTest extends IntegrationTest {

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    TransactionTemplate tx;

    @Test
    void baselineMigrationIsApplied() {
        Integer applied = jdbc.queryForObject(
                "SELECT count(*) FROM shsc.flyway_schema_history WHERE version IN ('001', '002', '003') AND success",
                Integer.class);
        assertThat(applied).isEqualTo(3);
    }

    @Test
    void runtimeRoleIsNotPrivileged() {
        Map<String, Object> role = jdbc.queryForMap(
                "SELECT current_user AS name, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
                        + "FROM pg_roles WHERE rolname = current_user");

        assertThat(role.get("name")).isEqualTo(PostgresTestContainer.APP_USER);
        assertThat(role.get("rolsuper")).isEqualTo(false);
        assertThat(role.get("rolbypassrls")).isEqualTo(false);
        assertThat(role.get("rolcreaterole")).isEqualTo(false);
        assertThat(role.get("rolcreatedb")).isEqualTo(false);
    }

    @Test
    void runtimeRoleCannotRunDdl() {
        assertThatThrownBy(() -> jdbc.execute("CREATE TABLE shsc.should_not_exist (id int)"))
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> jdbc.execute("CREATE TABLE public.should_not_exist (id int)"))
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void migrationHistoryIsOwnedByMigrator() {
        String owner = jdbc.queryForObject(
                "SELECT tableowner FROM pg_tables WHERE schemaname = 'shsc' AND tablename = 'flyway_schema_history'",
                String.class);
        assertThat(owner).isEqualTo(PostgresTestContainer.MIGRATOR_USER);
    }

    @Test
    void tenantContextIsNullWhenNotSet() {
        UUID tenant = tx.execute(status -> jdbc.queryForObject("SELECT shsc.current_tenant_id()", UUID.class));
        assertThat(tenant).isNull();
    }

    @Test
    void tenantContextIsScopedToTheTransaction() {
        UUID expected = UUID.randomUUID();

        UUID inside = tx.execute(status -> {
            jdbc.queryForObject("SELECT set_config('app.tenant_id', ?, true)", String.class, expected.toString());
            return jdbc.queryForObject("SELECT shsc.current_tenant_id()", UUID.class);
        });
        UUID afterwards = tx.execute(status -> jdbc.queryForObject("SELECT shsc.current_tenant_id()", UUID.class));

        assertThat(inside).isEqualTo(expected);
        assertThat(afterwards).isNull();
    }

    @Test
    void everyTenantScopedTableHasRowLevelSecurity() {
        java.util.List<String> unprotected = jdbc.queryForList("""
                SELECT c.relname FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'shsc' AND c.relkind = 'r' AND NOT c.relrowsecurity
                  AND (c.relname = 'tenants' OR EXISTS (SELECT 1 FROM pg_attribute a
                       WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
                """, String.class);
        assertThat(unprotected).isEmpty();
    }

    @Test
    void securityDefinerFunctionsAreNotExecutableByPublic() {
        Integer publicExecutable = jdbc.queryForObject("""
                SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'shsc' AND p.prosecdef
                  AND has_function_privilege('public', p.oid, 'EXECUTE')""", Integer.class);
        assertThat(publicExecutable).isZero();
    }

    @Test
    void trustedExtensionsAreInstalled() {
        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM pg_extension WHERE extname IN ('citext', 'pg_trgm')", Integer.class);
        assertThat(count).isEqualTo(2);
    }
}
