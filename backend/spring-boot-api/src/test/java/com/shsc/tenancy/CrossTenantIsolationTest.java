package com.shsc.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;

/**
 * IDOR check across organizations: every endpoint that takes an identifier is called by the
 * administrator of another business tenant and by a SUPER_ADMIN of that other tenant, using
 * the real identifiers of the victim tenant. Reads, updates, deletes and state changes must all
 * answer 404 (the resource does not exist for them), foreign identifiers inside request bodies
 * must be rejected, and afterwards the victim's data must be exactly as before.
 * <p>
 * The SUPER_ADMIN case documents that, up to this milestone, platform administration has no
 * cross-tenant path in the tenant API: Row-Level Security binds every request to the caller's
 * own tenant (the dedicated, audited {@code /admin/**} API is planned for a later milestone).
 */
class CrossTenantIsolationTest extends IntegrationTest {

    @Autowired
    Fixtures fixtures;

    @Test
    void anotherOrganizationCannotReadChangeOrDeleteAnythingByChangingIds() {
        // victim tenant with one resource of every kind
        Account victim = accounts().business("Vittima Srl");
        String customer = Fixtures.createCustomer(victim, "Cliente della vittima");
        String home = Fixtures.createHome(victim, Map.of("name", "Casa della vittima", "customerId", customer));
        String network = Fixtures.createNetwork(victim, home, "192.168.10.0/24");
        assertThat(victim.api().post("/api/v1/networks/" + network + "/authorization", attestation()).status())
                .isEqualTo(200);
        Response invited = victim.api().post("/api/v1/users", Map.of("email", "invitato-" + home.substring(0, 8)
                + "@example.test", "displayName", "Invitato", "locale", "it", "role", "READ_ONLY",
                "scopeType", "TENANT"));
        assertThat(invited.status()).as(invited.body()).isEqualTo(201);
        String invitedUser = invited.text("id");
        String victimAdmin = victim.userId().toString();
        String assignment = victim.api().get("/api/v1/users/" + victimAdmin + "/roles").json().get(0)
                .get("id").asString();
        Response token = victim.api().post("/api/v1/homes/" + home + "/agent-enrollment-tokens", Map.of());
        assertThat(token.status()).as(token.body()).isEqualTo(201);
        String tokenId = token.text("id");
        String agent = fixtures.addActiveAgent(victim.tenantId(), java.util.UUID.fromString(home)).toString();
        Map<String, String> before = snapshot(victim, customer, home, network, invitedUser);

        // attackers: the admin of another organization and a SUPER_ADMIN of that organization
        Account other = accounts().business("Attaccante Srl");
        Map<String, Account> attackers = new LinkedHashMap<>();
        attackers.put("ORGANIZATION_ADMIN", other);
        attackers.put("SUPER_ADMIN", fixtures.addUser(accounts(), client(), other, "SUPER_ADMIN",
                ScopeType.PLATFORM, null));

        List<Object[]> requests = List.of(
                req("GET", "/api/v1/customers/" + customer, null),
                req("PUT", "/api/v1/customers/" + customer, Map.of("displayName", "Rubato")),
                req("DELETE", "/api/v1/customers/" + customer, null),
                req("GET", "/api/v1/homes/" + home, null),
                req("PUT", "/api/v1/homes/" + home, Map.of("name", "Rubata", "timezone", "Europe/Rome")),
                req("DELETE", "/api/v1/homes/" + home, null),
                req("GET", "/api/v1/homes/" + home + "/networks", null),
                req("POST", "/api/v1/homes/" + home + "/networks",
                        Map.of("name", "Intrusa", "cidr", "10.9.0.0/24", "kind", "WIFI")),
                req("PUT", "/api/v1/networks/" + network, Map.of("name", "Rubata", "kind", "ETHERNET")),
                req("DELETE", "/api/v1/networks/" + network + "/authorization", null),
                req("POST", "/api/v1/networks/" + network + "/authorization", attestation()),
                req("DELETE", "/api/v1/networks/" + network, null),
                req("GET", "/api/v1/users/" + invitedUser, null),
                req("PATCH", "/api/v1/users/" + victimAdmin, Map.of("status", "DISABLED")),
                req("PATCH", "/api/v1/users/" + invitedUser, Map.of("displayName", "Rubato")),
                req("POST", "/api/v1/users/" + invitedUser + "/invitation", Map.of()),
                req("GET", "/api/v1/users/" + victimAdmin + "/roles", null),
                req("POST", "/api/v1/users/" + victimAdmin + "/roles", Map.of("role", "READ_ONLY",
                        "scopeType", "TENANT")),
                req("DELETE", "/api/v1/users/" + victimAdmin + "/roles/" + assignment, null),
                req("GET", "/api/v1/homes/" + home + "/agent-enrollment-tokens", null),
                req("POST", "/api/v1/homes/" + home + "/agent-enrollment-tokens", Map.of()),
                req("DELETE", "/api/v1/agent-enrollment-tokens/" + tokenId, null),
                req("GET", "/api/v1/homes/" + home + "/agents", null),
                req("GET", "/api/v1/agents/" + agent, null),
                req("POST", "/api/v1/agents/" + agent + "/revoke", Map.of("reason", "attacco")));

        for (Map.Entry<String, Account> attacker : attackers.entrySet()) {
            for (Object[] r : requests) {
                Response response = attacker.getValue().api().send((String) r[0], (String) r[1], r[2], Map.of());
                assertThat(response.status()).as("%s %s as %s -> %s", r[0], r[1], attacker.getKey(), response.body())
                        .isEqualTo(404);
            }
            Account a = attacker.getValue();
            // foreign identifiers inside request bodies are rejected as unknown
            Map<String, Object> foreignCustomer = new HashMap<>(Map.of("name", "Casa", "customerId", customer));
            Response homeWithForeignCustomer = a.api().post("/api/v1/homes", foreignCustomer);
            assertThat(homeWithForeignCustomer.status()).isEqualTo(400);
            assertThat(homeWithForeignCustomer.text("code")).isEqualTo("INVALID_CUSTOMER");
            for (Map<String, Object> scope : List.of(
                    Map.<String, Object>of("role", "TECHNICIAN", "scopeType", "CUSTOMER", "scopeId", customer),
                    Map.<String, Object>of("role", "TECHNICIAN", "scopeType", "HOME", "scopeId", home))) {
                Response grant = a.api().post("/api/v1/users/" + a.userId() + "/roles", scope);
                assertThat(grant.status()).as(grant.body()).isEqualTo(400);
                assertThat(grant.text("code")).isEqualTo("INVALID_SCOPE");
            }
            // lists and the audit log never contain the victim's data
            for (String list : List.of("/api/v1/customers", "/api/v1/homes", "/api/v1/users", "/api/v1/audit-logs")) {
                Response listed = a.api().get(list);
                assertThat(listed.status()).isEqualTo(200);
                assertThat(listed.body()).as(list).doesNotContain(customer).doesNotContain(home)
                        .doesNotContain(network).doesNotContain(invitedUser).doesNotContain(victimAdmin);
            }
            // "current" endpoints are always the caller's own tenant
            assertThat(a.api().get("/api/v1/tenants/current").text("id")).isEqualTo(other.tenantId().toString());
            assertThat(a.api().put("/api/v1/organizations/current", Map.of("legalName", "Attaccante Srl")).status())
                    .isEqualTo(200);
        }

        // the victim's data is untouched
        assertThat(snapshot(victim, customer, home, network, invitedUser)).isEqualTo(before);
        assertThat(victim.api().get("/api/v1/organizations/current").text("legalName")).isEqualTo("Vittima Srl");
        assertThat(victim.api().get("/api/v1/agents/" + agent).text("status")).isEqualTo("ACTIVE");
        assertThat(victim.api().get("/api/v1/users/" + victimAdmin).text("status")).isEqualTo("ACTIVE");
        assertThat(victim.api().get("/api/v1/users/" + victimAdmin + "/roles").json().size()).isEqualTo(1);
        assertThat(victim.api().get("/api/v1/homes/" + home + "/networks").json().size()).isEqualTo(1);
        assertThat(victim.api().get("/api/v1/homes/" + home + "/agent-enrollment-tokens").body())
                .doesNotContain("REVOKED");
    }

    private static Map<String, String> snapshot(Account victim, String customer, String home, String network,
            String invitedUser) {
        Map<String, String> state = new LinkedHashMap<>();
        state.put("customer", victim.api().get("/api/v1/customers/" + customer).body());
        state.put("home", victim.api().get("/api/v1/homes/" + home).body());
        state.put("networks", victim.api().get("/api/v1/homes/" + home + "/networks").body());
        state.put("user", victim.api().get("/api/v1/users/" + invitedUser).body());
        assertThat(state.get("networks")).as("network %s", network).contains("\"authorized\":true");
        return state;
    }

    private static Object[] req(String method, String path, Object body) {
        return new Object[] {method, path, body};
    }

    private static Map<String, Object> attestation() {
        return Map.of("attestation", true, "attestationVersion", "1");
    }
}
