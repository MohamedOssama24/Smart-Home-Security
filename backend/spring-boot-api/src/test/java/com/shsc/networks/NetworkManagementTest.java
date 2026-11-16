package com.shsc.networks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;

/**
 * Declared networks (Milestone 4): only private ranges, no overlaps, plan limit, explicit
 * versioned attestation for the authorization, permissions per role and scope, tenant
 * isolation and the database constraints as a second barrier.
 */
class NetworkManagementTest extends IntegrationTest {

    @Autowired
    Fixtures fixtures;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    TenantScope tenantScope;

    @Test
    void declaresPrivateNetworksAndRefusesPublicOverlappingOrTooMany() {
        Account admin = accounts().individual();
        String homeId = Fixtures.createHome(admin, "Casa Reti");

        Response created = admin.api().post(networksOf(homeId), network("Wi-Fi casa", "192.168.1.0/24"));
        assertThat(created.status()).as(created.body()).isEqualTo(201);
        assertThat(created.text("cidr")).isEqualTo("192.168.1.0/24");
        assertThat(created.text("source")).isEqualTo("MANUAL");
        assertThat(created.text("kind")).isEqualTo("WIFI");
        assertThat(created.json().get("ipVersion").asInt()).isEqualTo(4);
        assertThat(created.json().get("authorized").asBoolean()).isFalse();

        Response publicRange = admin.api().post(networksOf(homeId), network("Pubblica", "8.8.8.0/24"));
        assertThat(publicRange.status()).isEqualTo(400);
        assertThat(publicRange.text("code")).isEqualTo("NETWORK_NOT_PRIVATE");

        Response tooLarge = admin.api().post(networksOf(homeId), network("Enorme", "10.0.0.0/8"));
        assertThat(tooLarge.status()).isEqualTo(400);
        assertThat(tooLarge.text("code")).isEqualTo("NETWORK_TOO_LARGE");

        Response overlap = admin.api().post(networksOf(homeId), network("Sottorete", "192.168.1.128/25"));
        assertThat(overlap.status()).isEqualTo(409);
        assertThat(overlap.text("code")).isEqualTo("NETWORK_OVERLAP");

        // FREE: at most 4 networks per home
        Fixtures.createNetwork(admin, homeId, "192.168.2.0/24");
        Fixtures.createNetwork(admin, homeId, "10.10.0.0/24");
        Fixtures.createNetwork(admin, homeId, "fd00:0:0:1::/64");
        Response fifth = admin.api().post(networksOf(homeId), network("Quinta", "172.16.0.0/24"));
        assertThat(fifth.status()).isEqualTo(409);
        assertThat(fifth.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
        assertThat(fifth.text("resource")).isEqualTo("NETWORKS_PER_HOME");

        // the same range is fine in another home of the tenant
        String otherHome = Fixtures.createHome(admin, "Casa Mare");
        Fixtures.createNetwork(admin, otherHome, "192.168.1.0/24");
        assertThat(admin.api().get(networksOf(homeId)).json().size()).isEqualTo(4);
    }

    @Test
    void networkCanBeRenamedButNotMovedToAnotherRangeAndCanBeDeleted() {
        Account admin = accounts().individual();
        String homeId = Fixtures.createHome(admin, "Casa Modifica");
        String id = Fixtures.createNetwork(admin, homeId, "192.168.50.0/24");

        Response renamed = admin.api().put("/api/v1/networks/" + id,
                Map.of("name", "Ospiti", "kind", "GUEST", "cidr", "8.8.8.0/24"));
        assertThat(renamed.status()).as(renamed.body()).isEqualTo(200);
        assertThat(renamed.text("name")).isEqualTo("Ospiti");
        assertThat(renamed.text("kind")).isEqualTo("GUEST");
        assertThat(renamed.text("cidr")).isEqualTo("192.168.50.0/24"); // the range is immutable

        assertThat(admin.api().delete("/api/v1/networks/" + id).status()).isEqualTo(204);
        assertThat(admin.api().get(networksOf(homeId)).json().size()).isZero();
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("NETWORK_CREATED")
                .contains("NETWORK_UPDATED").contains("NETWORK_DELETED");
    }

    @Test
    void authorizationRequiresTheCurrentExplicitAttestationAndIsAudited() {
        Account admin = accounts().individual();
        String homeId = Fixtures.createHome(admin, "Casa Autorizzata");
        String id = Fixtures.createNetwork(admin, homeId, "192.168.10.0/24");
        String path = "/api/v1/networks/" + id + "/authorization";

        Response missing = admin.api().post(path, Map.of("attestation", false, "attestationVersion", "1"));
        assertThat(missing.status()).isEqualTo(400);
        assertThat(missing.text("code")).isEqualTo("ATTESTATION_REQUIRED");
        Response outdated = admin.api().post(path, Map.of("attestation", true, "attestationVersion", "0"));
        assertThat(outdated.status()).isEqualTo(400);
        assertThat(outdated.text("code")).isEqualTo("ATTESTATION_OUTDATED");
        Response noVersion = admin.api().post(path, Map.of("attestation", true));
        assertThat(noVersion.text("code")).isEqualTo("ATTESTATION_OUTDATED");

        Response authorized = admin.api().post(path, attestation());
        assertThat(authorized.status()).as(authorized.body()).isEqualTo(200);
        assertThat(authorized.json().get("authorized").asBoolean()).isTrue();
        assertThat(authorized.json().get("authorization").get("authorizedBy").asString())
                .isEqualTo(admin.userId().toString());
        assertThat(authorized.json().get("authorization").get("attestationVersion").asString()).isEqualTo("1");

        Response twice = admin.api().post(path, attestation());
        assertThat(twice.status()).isEqualTo(409);
        assertThat(twice.text("code")).isEqualTo("NETWORK_ALREADY_AUTHORIZED");

        Response revoked = admin.api().delete(path);
        assertThat(revoked.status()).isEqualTo(200);
        assertThat(revoked.json().get("authorized").asBoolean()).isFalse();
        Response revokedAgain = admin.api().delete(path);
        assertThat(revokedAgain.status()).isEqualTo(409);
        assertThat(revokedAgain.text("code")).isEqualTo("NETWORK_NOT_AUTHORIZED");

        // it can be authorized again; the history keeps both records
        assertThat(admin.api().post(path, attestation()).status()).isEqualTo(200);
        Integer history = tenantScope.callAs(admin.tenantId(), () -> tx.execute(s -> jdbc.sql(
                "SELECT count(*) FROM network_authorizations WHERE network_id = :id")
                .param("id", UUID.fromString(id)).query(Integer.class).single()));
        assertThat(history).isEqualTo(2);
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("NETWORK_AUTHORIZED")
                .contains("NETWORK_AUTHORIZATION_REVOKED");
    }

    @Test
    void readOnlyUsersSeeNetworksButCannotChangeThem() {
        Account admin = accounts().business("Reti Sola Lettura Srl");
        String homeId = Fixtures.createHome(admin, "Casa Cliente");
        String id = Fixtures.createNetwork(admin, homeId, "192.168.3.0/24");
        Account reader = fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.TENANT, null);

        assertThat(reader.api().get(networksOf(homeId)).json().size()).isEqualTo(1);
        assertThat(reader.api().post(networksOf(homeId), network("Nuova", "192.168.4.0/24")).status())
                .isEqualTo(403);
        assertThat(reader.api().put("/api/v1/networks/" + id, Map.of("name", "X")).status()).isEqualTo(403);
        assertThat(reader.api().delete("/api/v1/networks/" + id).status()).isEqualTo(403);
        assertThat(reader.api().post("/api/v1/networks/" + id + "/authorization", attestation()).status())
                .isEqualTo(403);
    }

    @Test
    void homeScopedTechnicianManagesOnlyTheAssignedHome() {
        Account admin = accounts().business("Tecnico Casa Srl");
        String assigned = Fixtures.createHome(admin, "Casa Assegnata");
        String other = Fixtures.createHome(admin, "Casa Altrui");
        String otherNetwork = Fixtures.createNetwork(admin, other, "192.168.9.0/24");
        Account technician = fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.HOME,
                UUID.fromString(assigned));

        String own = Fixtures.createNetwork(technician, assigned, "192.168.8.0/24");
        assertThat(technician.api().post("/api/v1/networks/" + own + "/authorization", attestation()).status())
                .isEqualTo(200);

        // the other home does not exist for the technician
        assertThat(technician.api().get(networksOf(other)).status()).isEqualTo(404);
        assertThat(technician.api().post(networksOf(other), network("Intrusa", "192.168.7.0/24")).status())
                .isEqualTo(404);
        assertThat(technician.api().put("/api/v1/networks/" + otherNetwork, Map.of("name", "X")).status())
                .isEqualTo(404);
        assertThat(technician.api().post("/api/v1/networks/" + otherNetwork + "/authorization", attestation())
                .status()).isEqualTo(404);
    }

    @Test
    void networksOfAnotherTenantAreInvisible() {
        Account alice = accounts().individual();
        Account bob = accounts().individual();
        String homeId = Fixtures.createHome(alice, "Casa Alice");
        String id = Fixtures.createNetwork(alice, homeId, "192.168.1.0/24");

        assertThat(bob.api().get(networksOf(homeId)).status()).isEqualTo(404);
        assertThat(bob.api().post(networksOf(homeId), network("X", "192.168.2.0/24")).status()).isEqualTo(404);
        assertThat(bob.api().put("/api/v1/networks/" + id, Map.of("name", "X")).status()).isEqualTo(404);
        assertThat(bob.api().delete("/api/v1/networks/" + id).status()).isEqualTo(404);
        assertThat(bob.api().post("/api/v1/networks/" + id + "/authorization", attestation()).status())
                .isEqualTo(404);
        assertThat(bob.api().delete("/api/v1/networks/" + id + "/authorization").status()).isEqualTo(404);
        assertThat(alice.api().get(networksOf(homeId)).json().get(0).get("authorized").asBoolean()).isFalse();
    }

    @Test
    void databaseRefusesPublicOrOversizedRangesEvenBypassingTheApplication() {
        Account admin = accounts().individual();
        UUID homeId = UUID.fromString(Fixtures.createHome(admin, "Casa Vincoli"));

        for (String cidr : new String[] {"8.8.8.0/24", "100.64.0.0/24", "10.0.0.0/8", "2001:db8::/64"}) {
            assertThatThrownBy(() -> tenantScope.runAs(admin.tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql("""
                    INSERT INTO networks (tenant_id, home_id, name, cidr, kind, source, created_by)
                    VALUES (:tenant, :home, 'diretta', CAST(:cidr AS cidr), 'WIFI', 'MANUAL', :user)""")
                    .param("tenant", admin.tenantId()).param("home", homeId).param("cidr", cidr)
                    .param("user", admin.userId()).update())))
                    .as(cidr).isInstanceOf(DataIntegrityViolationException.class);
        }
    }

    private static String networksOf(String homeId) {
        return "/api/v1/homes/" + homeId + "/networks";
    }

    private static Map<String, Object> network(String name, String cidr) {
        return new HashMap<>(Map.of("name", name, "cidr", cidr, "kind", "WIFI"));
    }

    private static Map<String, Object> attestation() {
        return Map.of("attestation", true, "attestationVersion", NetworkService.ATTESTATION_VERSION);
    }
}
