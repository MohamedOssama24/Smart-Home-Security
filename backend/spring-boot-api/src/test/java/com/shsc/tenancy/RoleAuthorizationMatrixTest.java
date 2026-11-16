package com.shsc.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;

/**
 * Authorization matrix of the Milestone 4 API: one business tenant with an organization
 * administrator, a tenant-wide technician, a customer-scoped user (customer A only), a
 * tenant-wide read-only user and a user without roles. Every row states the expected status
 * for every role, so a change in the role model shows up as a precise failure.
 * <p>
 * Convention: a resource outside the user's scope answers 404 (it does not exist for them),
 * a visible resource without the needed permission answers 403.
 */
class RoleAuthorizationMatrixTest extends IntegrationTest {

    @Autowired
    Fixtures fixtures;

    private Map<String, Account> roles;
    private String customerA;
    private String customerB;
    private String homeA;
    private String homeB;
    private String networkA;
    private String networkB;

    @Test
    void everyRoleGetsExactlyItsPermissions() {
        Account admin = accounts().business("Matrice Ruoli Srl");
        customerA = Fixtures.createCustomer(admin, "Cliente A");
        customerB = Fixtures.createCustomer(admin, "Cliente B");
        homeA = Fixtures.createHome(admin, Map.of("name", "Casa A", "customerId", customerA));
        homeB = Fixtures.createHome(admin, Map.of("name", "Casa B", "customerId", customerB));
        networkA = Fixtures.createNetwork(admin, homeA, "192.168.1.0/24");
        networkB = Fixtures.createNetwork(admin, homeB, "192.168.1.0/24");

        roles = new LinkedHashMap<>();
        roles.put("ADMIN", admin);
        roles.put("TECH", fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.TENANT, null));
        roles.put("CUST", fixtures.addUser(accounts(), client(), admin, "CUSTOMER", ScopeType.CUSTOMER,
                UUID.fromString(customerA)));
        roles.put("READ", fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.TENANT, null));
        roles.put("NONE", fixtures.addUser(accounts(), client(), admin, "NONE", null, null));
        String someUser = roles.get("READ").userId().toString();

        //                                                                   ADMIN TECH CUST READ NONE
        // users (FREE plan: the tenant is already over 3 users, so the invitation of the admin hits the limit)
        row("GET", "/api/v1/users", null,                                     200, 403, 403, 403, 403);
        row("GET", "/api/v1/users/" + someUser, null,                         200, 403, 403, 403, 403);
        row("PATCH", "/api/v1/users/" + someUser, Map.of("displayName", "Nuovo nome"),
                                                                              200, 403, 403, 403, 403);
        row("POST", "/api/v1/users", Map.of("email", "nessuno@example.invalid", "displayName", "X", "locale", "it",
                "role", "READ_ONLY", "scopeType", "TENANT"),                  409, 403, 403, 403, 403);
        // organization and plan
        row("GET", "/api/v1/tenants/current", null,                           200, 200, 200, 200, 403);
        row("GET", "/api/v1/organizations/current", null,                     200, 200, 200, 200, 403);
        row("PUT", "/api/v1/organizations/current", Map.of("legalName", "Matrice Ruoli Srl"),
                                                                              200, 403, 403, 403, 403);
        // customers
        row("GET", "/api/v1/customers", null,                                 200, 200, 200, 200, 403);
        row("GET", "/api/v1/customers/" + customerA, null,                    200, 200, 200, 200, 404);
        row("GET", "/api/v1/customers/" + customerB, null,                    200, 200, 404, 200, 404);
        row("PUT", "/api/v1/customers/" + customerA, Map.of("displayName", "Cliente A"),
                                                                              200, 403, 403, 403, 404);
        row("POST", "/api/v1/customers", Map.of("displayName", "Cliente C"),  409, 403, 403, 403, 403);
        // homes
        row("GET", "/api/v1/homes", null,                                     200, 200, 200, 200, 403);
        row("GET", "/api/v1/homes/" + homeA, null,                            200, 200, 200, 200, 404);
        row("GET", "/api/v1/homes/" + homeB, null,                            200, 200, 404, 200, 404);
        row("PUT", "/api/v1/homes/" + homeA, home("Casa A", customerA),       200, 200, 200, 403, 404);
        row("PUT", "/api/v1/homes/" + homeB, home("Casa B", customerB),       200, 200, 404, 403, 404);
        row("POST", "/api/v1/homes", Map.of("name", "Casa senza cliente"),    409, 409, 403, 403, 403);
        // networks
        row("GET", "/api/v1/homes/" + homeA + "/networks", null,              200, 200, 200, 200, 404);
        row("GET", "/api/v1/homes/" + homeB + "/networks", null,              200, 200, 404, 200, 404);
        row("PUT", "/api/v1/networks/" + networkA, Map.of("name", "Rete A", "kind", "WIFI"),
                                                                              200, 200, 200, 403, 404);
        row("PUT", "/api/v1/networks/" + networkB, Map.of("name", "Rete B", "kind", "WIFI"),
                                                                              200, 200, 404, 403, 404);
        row("POST", "/api/v1/networks/" + networkB + "/authorization", attestation(),
                                                                              200, 409, 404, 403, 404);
        row("DELETE", "/api/v1/networks/" + networkB + "/authorization", null,
                                                                              200, 409, 404, 403, 404);
        row("POST", "/api/v1/networks/" + networkA + "/authorization", attestation(),
                                                                              200, 409, 409, 403, 404);

        // the customer user and the read-only user see only what their scope allows
        assertThat(roles.get("CUST").api().get("/api/v1/homes").json().size()).isEqualTo(1);
        assertThat(roles.get("CUST").api().get("/api/v1/customers").json().size()).isEqualTo(1);
        assertThat(roles.get("TECH").api().get("/api/v1/homes").json().size()).isEqualTo(2);
        // usage figures only for tenant-wide readers
        assertThat(roles.get("CUST").api().get("/api/v1/tenants/current").json().get("usage").isNull()).isTrue();
        assertThat(roles.get("READ").api().get("/api/v1/tenants/current").json().get("usage").get("homes").asInt())
                .isEqualTo(2);
    }

    /**
     * Sends the same request as every role in order and checks the expected status. Rows run
     * in sequence, so a row that changes state (e.g. an authorization) is written so that the
     * statuses of the following roles reflect that state.
     */
    private void row(String method, String path, Object body, int... expected) {
        int i = 0;
        for (Map.Entry<String, Account> role : roles.entrySet()) {
            Response response = role.getValue().api().send(method, path, body, Map.of());
            assertThat(response.status()).as("%s %s as %s -> %s", method, path, role.getKey(), response.body())
                    .isEqualTo(expected[i++]);
        }
    }

    private static Map<String, Object> home(String name, String customerId) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        body.put("customerId", customerId);
        body.put("timezone", "Europe/Rome");
        return body;
    }

    private static Map<String, Object> attestation() {
        return Map.of("attestation", true, "attestationVersion", "1");
    }
}
