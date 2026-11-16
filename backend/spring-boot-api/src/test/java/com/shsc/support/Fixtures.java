package com.shsc.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.TestAccounts.Account;

/**
 * Test data that cannot (or should not) go through the public API in every test: users
 * inserted directly in a tenant (bypassing invitations and plan limits, to test permissions
 * of many roles in one tenant) and active agents (enrollment is covered by its own tests).
 */
@Component
public class Fixtures {

    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final JdbcClient jdbc;
    private final UserRepository users;
    private final RoleAssignmentRepository assignments;
    private final PasswordEncoder encoder;

    public Fixtures(TenantScope tenantScope, TransactionTemplate tx, JdbcClient jdbc, UserRepository users,
            RoleAssignmentRepository assignments, PasswordEncoder encoder) {
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.jdbc = jdbc;
        this.users = users;
        this.assignments = assignments;
        this.encoder = encoder;
    }

    /** Adds a verified user with one role to the admin's tenant and signs it in. */
    public Account addUser(TestAccounts accounts, ApiClient client, Account admin, String role, ScopeType scope,
            UUID scopeId) {
        String email = TestAccounts.uniqueEmail(role.toLowerCase());
        String hash = encoder.encode(TestAccounts.PASSWORD);
        tenantScope.runAs(admin.tenantId(), () -> tx.executeWithoutResult(s -> {
            Instant now = Instant.now();
            UUID id = users.insert(admin.tenantId(), email, hash, "Collega " + role, "it", now);
            users.markEmailVerified(id, now);
            if (role != null && !role.isEmpty() && !"NONE".equals(role)) {
                assignments.insert(admin.tenantId(), id, role, scope, scopeId, admin.userId(), now);
            }
        }));
        return accounts.login(client, email, TestAccounts.PASSWORD);
    }

    /** Inserts an ACTIVE agent bound to the home (as if it had enrolled). */
    public UUID addActiveAgent(UUID tenantId, UUID homeId) {
        return tenantScope.callAs(tenantId, () -> tx.execute(s -> jdbc.sql("""
                INSERT INTO agents (tenant_id, home_id, name, os, arch, agent_version)
                VALUES (:tenant, :home, 'agent di prova', 'linux', 'amd64', '1.0.0') RETURNING id""")
                .param("tenant", tenantId).param("home", homeId).query(UUID.class).single()));
    }

    public static String createHome(Account account, String name) {
        return createHome(account, Map.of("name", name));
    }

    public static String createHome(Account account, Map<String, Object> body) {
        Response response = account.api().post("/api/v1/homes", body);
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return response.text("id");
    }

    public static String createCustomer(Account account, String name) {
        Response response = account.api().post("/api/v1/customers", Map.of("displayName", name));
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return response.text("id");
    }

    public static String createNetwork(Account account, String homeId, String cidr) {
        Response response = account.api().post("/api/v1/homes/" + homeId + "/networks",
                Map.of("name", "Rete " + cidr, "cidr", cidr, "kind", "WIFI"));
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return response.text("id");
    }
}
