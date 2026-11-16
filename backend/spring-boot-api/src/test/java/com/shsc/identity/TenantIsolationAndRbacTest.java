package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.identity.user.UserRepository;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts;
import com.shsc.support.TestAccounts.Account;

/**
 * Tenant isolation (application + PostgreSQL RLS) and RBAC with TENANT / ORGANIZATION /
 * HOME scopes. Changing an ID in the URL never gives access to another tenant's data.
 */
class TenantIsolationAndRbacTest extends IntegrationTest {

    @Autowired
    JdbcClient jdbc;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    TenantScope tenantScope;

    @Autowired
    UserRepository users;

    @Autowired
    RoleAssignmentRepository assignments;

    @Autowired
    PasswordEncoder encoder;

    @Test
    void anotherTenantsHomeIsInvisible() {
        Account alice = accounts().individual();
        Account mallory = accounts().individual();
        String homeId = createHome(alice, "Casa di Alice");

        assertThat(alice.api().get("/api/v1/homes/" + homeId).status()).isEqualTo(200);
        assertThat(mallory.api().get("/api/v1/homes/" + homeId).status()).isEqualTo(404);
        assertThat(mallory.api().get("/api/v1/homes").json().size()).isZero();
        assertThat(mallory.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).status())
                .isEqualTo(404);
        assertThat(mallory.api().get("/api/v1/homes/" + homeId + "/agents").status()).isEqualTo(404);
        assertThat(mallory.api().get("/api/v1/users/" + alice.userId() + "/roles").status()).isIn(403, 404);
    }

    @Test
    void rowLevelSecurityHidesOtherTenantsEvenWithoutWhereClause() {
        Account alice = accounts().individual();
        Account bob = accounts().individual();
        createHome(alice, "Casa A");

        List<UUID> seenByBob = tenantScope.callAs(bob.tenantId(),
                () -> tx.execute(s -> jdbc.sql("SELECT tenant_id FROM homes UNION ALL SELECT tenant_id FROM users")
                        .query(UUID.class).list()));
        assertThat(seenByBob).isNotEmpty().allMatch(bob.tenantId()::equals);

        Integer withoutTenant = tx.execute(s -> jdbc.sql("SELECT count(*) FROM users").query(Integer.class).single());
        assertThat(withoutTenant).isZero();

        // writing a row for another tenant is refused by the policy WITH CHECK
        assertThatThrownBy(() -> tenantScope.runAs(bob.tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql(
                "INSERT INTO homes (tenant_id, name) VALUES (:t, 'intrusa')").param("t", alice.tenantId()).update())))
                .rootCause().hasMessageContaining("row-level security");
    }

    @Test
    void auditLogIsAppendOnlyAndTenantScoped() {
        Account alice = accounts().individual();
        Account bob = accounts().individual();

        Response bobAudit = bob.api().get("/api/v1/audit-logs");
        assertThat(bobAudit.body()).doesNotContain(alice.userId().toString());

        assertThatThrownBy(() -> tenantScope.runAs(alice.tenantId(), () -> tx.executeWithoutResult(s ->
                jdbc.sql("UPDATE audit_logs SET action = 'TAMPERED'").update())))
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> tenantScope.runAs(alice.tenantId(), () -> tx.executeWithoutResult(s ->
                jdbc.sql("DELETE FROM audit_logs").update())))
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void readOnlyUserCanReadButNotWrite() {
        Account admin = accounts().business("Rossi Impianti");
        String homeId = createHome(admin, "Cliente 1");
        Account viewer = addUser(admin, "READ_ONLY", ScopeType.TENANT, null);

        assertThat(viewer.api().get("/api/v1/homes").json().size()).isEqualTo(1);
        assertThat(viewer.api().get("/api/v1/homes/" + homeId).status()).isEqualTo(200);
        assertThat(viewer.api().post("/api/v1/homes", Map.of("name", "Nuova")).status()).isEqualTo(403);
        assertThat(viewer.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).status())
                .isEqualTo(403);
        assertThat(viewer.api().get("/api/v1/users").status()).isEqualTo(403);
        assertThat(viewer.api().get("/api/v1/audit-logs").status()).isEqualTo(403);
    }

    @Test
    void homeScopedTechnicianSeesOnlyAssignedHome() {
        Account admin = accounts().business("Bianchi Sicurezza");
        String assigned = createHome(admin, "Casa assegnata");
        String other = createHome(admin, "Altra casa");
        Account technician = addUser(admin, "TECHNICIAN", ScopeType.HOME, UUID.fromString(assigned));

        Response homes = technician.api().get("/api/v1/homes");
        assertThat(homes.json().size()).isEqualTo(1);
        assertThat(homes.json().get(0).get("id").asString()).isEqualTo(assigned);
        assertThat(technician.api().get("/api/v1/homes/" + other).status()).isEqualTo(404);
        assertThat(technician.api().post("/api/v1/homes/" + assigned + "/agent-enrollment-tokens", null).status())
                .isEqualTo(201);
        assertThat(technician.api().post("/api/v1/homes/" + other + "/agent-enrollment-tokens", null).status())
                .isEqualTo(404);
        // creating homes needs a tenant-wide scope
        assertThat(technician.api().post("/api/v1/homes", Map.of("name", "X")).status()).isEqualTo(403);
    }

    @Test
    void roleChangesApplyImmediatelyAndAreAudited() {
        Account admin = accounts().business("Verdi Srl");
        String homeId = createHome(admin, "Casa");
        Account user = addUser(admin, "READ_ONLY", ScopeType.HOME, UUID.fromString(homeId));
        assertThat(user.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).status())
                .isEqualTo(403);

        Response assigned = admin.api().post("/api/v1/users/" + user.userId() + "/roles",
                Map.of("role", "TECHNICIAN", "scopeType", "HOME", "scopeId", homeId));
        assertThat(assigned.status()).isEqualTo(201);
        // same access token, new permission
        assertThat(user.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).status())
                .isEqualTo(201);

        String assignmentId = assigned.text("id");
        assertThat(admin.api().delete("/api/v1/users/" + user.userId() + "/roles/" + assignmentId).status())
                .isEqualTo(204);
        assertThat(user.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).status())
                .isEqualTo(403);

        String audit = admin.api().get("/api/v1/audit-logs").body();
        assertThat(audit).contains("ROLE_ASSIGNED").contains("ROLE_REVOKED");
    }

    @Test
    void privilegeEscalationIsImpossible() {
        Account admin = accounts().business("Neri Spa");
        Account user = addUser(admin, "TECHNICIAN", ScopeType.TENANT, null);

        // the technician cannot manage roles at all
        assertThat(user.api().post("/api/v1/users/" + user.userId() + "/roles",
                Map.of("role", "ORGANIZATION_ADMIN", "scopeType", "TENANT")).status()).isEqualTo(403);
        // nobody can grant SUPER_ADMIN or PLATFORM scope through the API
        assertThat(admin.api().post("/api/v1/users/" + user.userId() + "/roles",
                Map.of("role", "SUPER_ADMIN", "scopeType", "PLATFORM")).status()).isEqualTo(403);
        // scope must be valid for the role
        assertThat(admin.api().post("/api/v1/users/" + user.userId() + "/roles",
                Map.of("role", "ORGANIZATION_ADMIN", "scopeType", "HOME", "scopeId", UUID.randomUUID().toString()))
                .text("code")).isEqualTo("INVALID_SCOPE");
        // a home of another tenant is not a valid scope
        Account stranger = accounts().individual();
        String foreignHome = createHome(stranger, "Estranea");
        assertThat(admin.api().post("/api/v1/users/" + user.userId() + "/roles",
                Map.of("role", "TECHNICIAN", "scopeType", "HOME", "scopeId", foreignHome)).text("code"))
                .isEqualTo("INVALID_SCOPE");
        // a user of another tenant cannot be targeted
        assertThat(admin.api().post("/api/v1/users/" + stranger.userId() + "/roles",
                Map.of("role", "READ_ONLY", "scopeType", "TENANT")).status()).isEqualTo(404);
    }

    @Test
    void lastOrganizationAdminCannotBeRemoved() {
        Account admin = accounts().business("Gialli Srl");
        String assignmentId = admin.api().get("/api/v1/users/" + admin.userId() + "/roles").json().get(0)
                .get("id").asString();
        Response response = admin.api().delete("/api/v1/users/" + admin.userId() + "/roles/" + assignmentId);
        assertThat(response.status()).isEqualTo(409);
        assertThat(response.text("code")).isEqualTo("LAST_ADMIN");
    }

    @Test
    void rolesCatalogueHidesPlatformRoles() {
        Account admin = accounts().business("Catalogo Srl");
        Response roles = admin.api().get("/api/v1/roles");
        assertThat(roles.body()).contains("ORGANIZATION_ADMIN").contains("TECHNICIAN").contains("CUSTOMER")
                .contains("READ_ONLY").doesNotContain("SUPER_ADMIN");
    }

    private String createHome(Account account, String name) {
        Response response = account.api().post("/api/v1/homes", Map.of("name", name));
        assertThat(response.status()).as(response.body()).isEqualTo(201);
        return response.text("id");
    }

    /** Adds a verified user to the admin's tenant (invitations arrive in Milestone 4). */
    private Account addUser(Account admin, String role, ScopeType scope, UUID scopeId) {
        String email = TestAccounts.uniqueEmail(role.toLowerCase());
        String hash = encoder.encode(TestAccounts.PASSWORD);
        tenantScope.runAs(admin.tenantId(), () -> tx.executeWithoutResult(s -> {
            Instant now = Instant.now();
            UUID id = users.insert(admin.tenantId(), email, hash, "Collega", "it", now);
            users.markEmailVerified(id, now);
            assignments.insert(admin.tenantId(), id, role, scope, scopeId, admin.userId(), now);
        }));
        return accounts().login(client(), email, TestAccounts.PASSWORD);
    }
}
