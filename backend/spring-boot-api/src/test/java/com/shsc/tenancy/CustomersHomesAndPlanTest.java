package com.shsc.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
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
 * Organizations, customers and homes (Milestone 4): B2B customers with CUSTOMER-scoped
 * users, home update / archive rules, FREE plan limits and tenant isolation.
 */
class CustomersHomesAndPlanTest extends IntegrationTest {

    @Autowired
    Fixtures fixtures;

    @Test
    void currentTenantShowsFreePlanLimitsAndUsage() {
        Account admin = accounts().business("Piano Srl");
        Fixtures.createHome(admin, "Casa 1");

        Response tenant = admin.api().get("/api/v1/tenants/current");
        assertThat(tenant.status()).isEqualTo(200);
        assertThat(tenant.text("type")).isEqualTo("BUSINESS");
        assertThat(tenant.json().get("plan").get("code").asString()).isEqualTo("FREE");
        assertThat(tenant.json().get("plan").get("maxHomes").asInt()).isEqualTo(2);
        assertThat(tenant.json().get("plan").get("maxUsers").asInt()).isEqualTo(3);
        assertThat(tenant.json().get("plan").get("maxCustomers").asInt()).isEqualTo(2);
        assertThat(tenant.json().get("plan").get("maxNetworksPerHome").asInt()).isEqualTo(4);
        assertThat(tenant.json().get("usage").get("homes").asInt()).isEqualTo(1);
        assertThat(tenant.json().get("usage").get("users").asInt()).isEqualTo(1);

        // a user limited to one home does not see how large the tenant is
        String homeId = admin.api().get("/api/v1/homes").json().get(0).get("id").asString();
        Account scoped = fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.HOME,
                UUID.fromString(homeId));
        Response limited = scoped.api().get("/api/v1/tenants/current");
        assertThat(limited.status()).isEqualTo(200);
        assertThat(limited.json().get("usage") == null || limited.json().get("usage").isNull()).isTrue();
        assertThat(limited.json().get("plan").get("code").asString()).isEqualTo("FREE");
    }

    @Test
    void organizationDetailsAreEditableOnlyByTheAdministrator() {
        Account admin = accounts().business("Vecchio Nome Srl");
        Account technician = fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.TENANT, null);

        Map<String, Object> body = Map.of("legalName", "Nuovo Nome Srl", "vatNumber", "it 01234567890",
                "contactEmail", "info@nuovonome.test", "contactPhone", "+39 02 1234567");
        Response updated = admin.api().put("/api/v1/organizations/current", body);
        assertThat(updated.status()).as(updated.body()).isEqualTo(200);
        assertThat(updated.text("vatNumber")).isEqualTo("IT01234567890");
        assertThat(admin.api().get("/api/v1/tenants/current").text("name")).isEqualTo("Nuovo Nome Srl");
        assertThat(technician.api().get("/api/v1/organizations/current").text("legalName")).isEqualTo("Nuovo Nome Srl");

        assertThat(technician.api().put("/api/v1/organizations/current", body).status()).isEqualTo(403);
        Response badVat = admin.api().put("/api/v1/organizations/current",
                Map.of("legalName", "X Srl", "vatNumber", "1"));
        assertThat(badVat.text("code")).isEqualTo("INVALID_VAT_NUMBER");

        // a private (B2C) account has no organization
        Account individual = accounts().individual();
        assertThat(individual.api().get("/api/v1/organizations/current").status()).isEqualTo(404);
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("ORGANIZATION_UPDATED");
    }

    @Test
    void customersExistOnlyForBusinessTenants() {
        Account individual = accounts().individual();
        Response refused = individual.api().post("/api/v1/customers", Map.of("displayName", "Cliente"));
        // a B2C owner does not hold customer:manage at all
        assertThat(refused.status()).isEqualTo(403);

        Account admin = accounts().business("Clienti Srl");
        Response created = admin.api().post("/api/v1/customers", Map.of("displayName", " Famiglia Rossi ",
                "contactEmail", "rossi@example.test", "contactPhone", "+39 333 1234567", "notes", "villetta"));
        assertThat(created.status()).as(created.body()).isEqualTo(201);
        assertThat(created.text("displayName")).isEqualTo("Famiglia Rossi");
        String id = created.text("id");

        Response updated = admin.api().put("/api/v1/customers/" + id, Map.of("displayName", "Famiglia Rossi B."));
        assertThat(updated.text("displayName")).isEqualTo("Famiglia Rossi B.");
        assertThat(updated.text("contactEmail")).isNull();
        assertThat(admin.api().get("/api/v1/customers").json().size()).isEqualTo(1);
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("CUSTOMER_CREATED").contains("CUSTOMER_UPDATED");
    }

    @Test
    void customerScopedUserSeesOnlyItsCustomerAndItsHomes() {
        Account admin = accounts().business("Installatore Srl");
        String rossi = Fixtures.createCustomer(admin, "Rossi");
        String bianchi = Fixtures.createCustomer(admin, "Bianchi");
        String casaRossi = Fixtures.createHome(admin, Map.of("name", "Casa Rossi", "customerId", rossi));
        String casaBianchi = Fixtures.createHome(admin, Map.of("name", "Casa Bianchi", "customerId", bianchi));
        Account owner = fixtures.addUser(accounts(), client(), admin, "CUSTOMER", ScopeType.CUSTOMER,
                UUID.fromString(rossi));

        Response customers = owner.api().get("/api/v1/customers");
        assertThat(customers.json().size()).isEqualTo(1);
        assertThat(customers.json().get(0).get("id").asString()).isEqualTo(rossi);
        assertThat(owner.api().get("/api/v1/customers/" + bianchi).status()).isEqualTo(404);

        Response homes = owner.api().get("/api/v1/homes");
        assertThat(homes.json().size()).isEqualTo(1);
        assertThat(homes.json().get(0).get("id").asString()).isEqualTo(casaRossi);
        assertThat(owner.api().get("/api/v1/homes/" + casaBianchi).status()).isEqualTo(404);
        assertThat(owner.api().get("/api/v1/homes?customerId=" + bianchi).json().size()).isZero();
        // permissions on the homes of the customer come from the CUSTOMER scope
        assertThat(owner.api().post("/api/v1/homes/" + casaRossi + "/agent-enrollment-tokens", null).status())
                .isEqualTo(201);
        assertThat(owner.api().post("/api/v1/homes/" + casaBianchi + "/agent-enrollment-tokens", null).status())
                .isEqualTo(404);
        // but never on the customer record itself
        assertThat(owner.api().put("/api/v1/customers/" + rossi, Map.of("displayName", "X")).status()).isEqualTo(403);
        assertThat(owner.api().post("/api/v1/customers", Map.of("displayName", "Nuovo")).status()).isEqualTo(403);
        // a home can be created only for its own customer
        assertThat(owner.api().post("/api/v1/homes", Map.of("name", "Seconda casa")).status()).isEqualTo(403);
        assertThat(owner.api().post("/api/v1/homes", Map.of("name", "Altra", "customerId", bianchi)).status())
                .isEqualTo(403);
    }

    @Test
    void technicianReadsCustomersButCannotManageThem() {
        Account admin = accounts().business("Tecnici Srl");
        String customer = Fixtures.createCustomer(admin, "Verdi");
        Account technician = fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.TENANT, null);
        Account viewer = fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.TENANT, null);

        assertThat(technician.api().get("/api/v1/customers/" + customer).status()).isEqualTo(200);
        assertThat(viewer.api().get("/api/v1/customers").json().size()).isEqualTo(1);
        assertThat(technician.api().post("/api/v1/customers", Map.of("displayName", "Nuovo")).status()).isEqualTo(403);
        assertThat(technician.api().delete("/api/v1/customers/" + customer).status()).isEqualTo(403);
        assertThat(viewer.api().put("/api/v1/customers/" + customer, Map.of("displayName", "X")).status())
                .isEqualTo(403);
        // a technician of the whole tenant can create homes for any customer
        assertThat(technician.api().post("/api/v1/homes", Map.of("name", "Casa Verdi", "customerId", customer))
                .status()).isEqualTo(201);
    }

    @Test
    void customerWithHomesCannotBeArchived() {
        Account admin = accounts().business("Archivio Srl");
        String customer = Fixtures.createCustomer(admin, "Neri");
        String home = Fixtures.createHome(admin, Map.of("name", "Casa Neri", "customerId", customer));

        Response refused = admin.api().delete("/api/v1/customers/" + customer);
        assertThat(refused.status()).isEqualTo(409);
        assertThat(refused.text("code")).isEqualTo("CUSTOMER_HAS_HOMES");

        assertThat(admin.api().delete("/api/v1/homes/" + home).status()).isEqualTo(204);
        assertThat(admin.api().delete("/api/v1/customers/" + customer).status()).isEqualTo(204);
        assertThat(admin.api().get("/api/v1/customers/" + customer).status()).isEqualTo(404);
        // an archived customer is not a valid target any more
        Response invalid = admin.api().post("/api/v1/homes", Map.of("name", "Y", "customerId", customer));
        assertThat(invalid.text("code")).isEqualTo("INVALID_CUSTOMER");
    }

    @Test
    void homesCanBeUpdatedMovedAndArchived() {
        Account admin = accounts().business("Case Srl");
        String customerA = Fixtures.createCustomer(admin, "A");
        String customerB = Fixtures.createCustomer(admin, "B");
        String home = Fixtures.createHome(admin, Map.of("name", "Casa", "customerId", customerA));
        assertThat(admin.api().get("/api/v1/homes/" + home).text("timezone")).isEqualTo("Europe/Rome");

        Map<String, Object> update = new HashMap<>(Map.of("name", "Casa al mare", "address", "Via Roma 1, Rimini",
                "timezone", "Europe/Rome", "customerId", customerB));
        Response updated = admin.api().put("/api/v1/homes/" + home, update);
        assertThat(updated.status()).as(updated.body()).isEqualTo(200);
        assertThat(updated.text("name")).isEqualTo("Casa al mare");
        assertThat(updated.text("customerId")).isEqualTo(customerB);
        assertThat(admin.api().get("/api/v1/homes?customerId=" + customerA).json().size()).isZero();

        update.put("timezone", "Marte/Olympus");
        assertThat(admin.api().put("/api/v1/homes/" + home, update).text("code")).isEqualTo("INVALID_TIMEZONE");

        // HOME scope: can edit the home, cannot move it to another customer nor archive it
        Account technician = fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.HOME,
                UUID.fromString(home));
        assertThat(technician.api().put("/api/v1/homes/" + home, Map.of("name", "Rinominata",
                "customerId", customerB)).status()).isEqualTo(200);
        assertThat(technician.api().put("/api/v1/homes/" + home, Map.of("name", "Spostata",
                "customerId", customerA)).status()).isEqualTo(403);
        assertThat(technician.api().delete("/api/v1/homes/" + home).status()).isEqualTo(403);

        // a home with an active agent cannot be archived
        fixtures.addActiveAgent(admin.tenantId(), UUID.fromString(home));
        Response withAgent = admin.api().delete("/api/v1/homes/" + home);
        assertThat(withAgent.status()).isEqualTo(409);
        assertThat(withAgent.text("code")).isEqualTo("HOME_HAS_ACTIVE_AGENTS");
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("HOME_UPDATED");
    }

    @Test
    void freePlanLimitsHomesAndCustomers() {
        Account admin = accounts().business("Limiti Srl");
        Fixtures.createHome(admin, "Casa 1");
        String second = Fixtures.createHome(admin, "Casa 2");
        Response third = admin.api().post("/api/v1/homes", Map.of("name", "Casa 3"));
        assertThat(third.status()).isEqualTo(409);
        assertThat(third.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
        assertThat(third.text("resource")).isEqualTo("HOMES");
        // archiving frees the slot
        assertThat(admin.api().delete("/api/v1/homes/" + second).status()).isEqualTo(204);
        Fixtures.createHome(admin, "Casa 3");

        Fixtures.createCustomer(admin, "C1");
        Fixtures.createCustomer(admin, "C2");
        Response customer = admin.api().post("/api/v1/customers", Map.of("displayName", "C3"));
        assertThat(customer.status()).isEqualTo(409);
        assertThat(customer.text("resource")).isEqualTo("CUSTOMERS");
    }

    @Test
    void customersAndHomesOfAnotherTenantAreInvisible() {
        Account alice = accounts().business("Alfa Clienti");
        Account bob = accounts().business("Beta Clienti");
        String customer = Fixtures.createCustomer(alice, "Cliente di Alfa");
        String home = Fixtures.createHome(alice, Map.of("name", "Casa di Alfa", "customerId", customer));

        assertThat(bob.api().get("/api/v1/customers/" + customer).status()).isEqualTo(404);
        assertThat(bob.api().put("/api/v1/customers/" + customer, Map.of("displayName", "X")).status()).isEqualTo(404);
        assertThat(bob.api().delete("/api/v1/customers/" + customer).status()).isEqualTo(404);
        assertThat(bob.api().put("/api/v1/homes/" + home, Map.of("name", "X")).status()).isEqualTo(404);
        assertThat(bob.api().delete("/api/v1/homes/" + home).status()).isEqualTo(404);
        // another tenant's customer is not a valid reference
        assertThat(bob.api().post("/api/v1/homes", Map.of("name", "X", "customerId", customer)).text("code"))
                .isEqualTo("INVALID_CUSTOMER");
        assertThat(bob.api().post("/api/v1/users/" + bob.userId() + "/roles",
                Map.of("role", "READ_ONLY", "scopeType", "CUSTOMER", "scopeId", customer)).text("code"))
                .isEqualTo("INVALID_SCOPE");
        assertThat(bob.api().get("/api/v1/customers").json().size()).isZero();
    }
}
