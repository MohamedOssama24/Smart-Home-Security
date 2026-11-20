package com.shsc.people;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * Accounts seen by the agent on the addresses of the home (Active Directory logons, Sophos
 * authentications: ADR-083) become PROBABLE people of the device with that address. [MOCK] data:
 * 192.168.66.0/24 authorized, 192.168.67.0/24 not; invented accounts.
 */
class AccountIdentitiesTest extends IntegrationTest {

    private static final String PC = "00:11:22:00:66:21";
    private static final String LAPTOP = "00:11:22:00:66:22";

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private static Map<String, Object> identity(String ip, String account, String source) {
        return Map.of("ip", ip, "account", account, "source", source, "observedAt", Instant.now().toString());
    }

    private static Map<String, Object> arp(String ip, String mac) {
        return new HashMap<>(Map.of("ip", ip, "mac", mac, "method", "ARP", "observedAt", Instant.now().toString()));
    }

    private static JsonNode person(JsonNode people, String name) {
        for (JsonNode p : people) {
            if (p.get("name").asString().equals(name)) {
                return p;
            }
        }
        throw new AssertionError(name + " not in " + people);
    }

    @Test
    void accountsSeenOnTheAddressesBecomeProbablePeople() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Ufficio identità");
        String network = Fixtures.createNetwork(owner, home, "192.168.66.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.9.0", "uptimeSeconds", 5, "interfacesHash", "e".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of(),
                        "routerIntegrations", List.of()))).status()).isEqualTo(200);

        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String base = "/api/v1/agent/scans/" + created.text("id");
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", List.of(arp("192.168.66.21", PC), arp("192.168.66.22", LAPTOP)))).status())
                .isEqualTo(200);

        // identities never travel with hosts, and need a valid account
        Response mixed = agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(arp("192.168.66.23", "00:11:22:00:66:23")),
                "identities", List.of(identity("192.168.66.21", "mario.rossi", "DIRECTORY"))));
        assertThat(mixed.status()).as(mixed.body()).isEqualTo(400);
        assertThat(agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "identities", List.of(identity("192.168.66.21", "CORP\\mario", "DIRECTORY"))))
                .status()).isEqualTo(400);

        Response ids = agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "identities", List.of(
                        identity("192.168.66.21", "mario.rossi", "DIRECTORY"),
                        identity("192.168.66.22", "anna.bianchi", "FIREWALL"),
                        identity("192.168.66.22", "Mario.Rossi", "DIRECTORY"), // same account, other device
                        identity("192.168.66.99", "nessuno", "FIREWALL"), // no device with this address
                        identity("192.168.67.5", "fuori.rete", "DIRECTORY")))); // outside the authorized networks
        assertThat(ids.status()).as(ids.body()).isEqualTo(200);
        assertThat(ids.json().get("dropped").asInt()).isEqualTo(1);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);

        JsonNode devices = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        String pc = null;
        String laptop = null;
        for (JsonNode d : devices) {
            if (d.get("mac").asString().equals(PC)) {
                pc = d.get("id").asString();
            } else if (d.get("mac").asString().equals(LAPTOP)) {
                laptop = d.get("id").asString();
            }
        }
        JsonNode people = owner.api().get("/api/v1/homes/" + home + "/people").json();
        assertThat(people.size()).as(people.toString()).isEqualTo(2); // nobody for .99 and .67.5
        JsonNode mario = person(people, "mario.rossi");
        assertThat(mario.get("origin").asString()).isEqualTo("DIRECTORY");
        assertThat(mario.get("devices").size()).isEqualTo(2);
        for (JsonNode link : mario.get("devices")) {
            assertThat(link.get("status").asString()).isEqualTo("PROBABLE");
            assertThat(link.get("source").asString()).isEqualTo("DIRECTORY");
            assertThat(link.get("deviceId").asString()).isIn(pc, laptop);
        }
        JsonNode anna = person(people, "anna.bianchi");
        assertThat(anna.get("origin").asString()).isEqualTo("FIREWALL");
        assertThat(anna.get("devices").get(0).get("deviceId").asString()).isEqualTo(laptop);
        assertThat(anna.get("devices").get(0).get("evidence").asString()).startsWith("anna.bianchi @ 192.168.66.22, ");

        // a person the user deleted is not proposed again by the next scans
        assertThat(owner.api().delete("/api/v1/people/" + anna.get("id").asString()).status()).isEqualTo(204);
        Response again = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        String base2 = "/api/v1/agent/scans/" + again.text("id");
        assertThat(agents().as(agent).post(base2 + "/ack", null).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base2 + "/results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", List.of(arp("192.168.66.22", LAPTOP)))).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base2 + "/results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "identities", List.of(identity("192.168.66.22", "anna.bianchi", "FIREWALL"))))
                .status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base2 + "/complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of())).status()).isEqualTo(200);
        JsonNode after = owner.api().get("/api/v1/homes/" + home + "/people").json();
        assertThat(after.size()).as(after.toString()).isEqualTo(1);
        assertThat(after.get(0).get("name").asString()).isEqualTo("mario.rossi");
    }
}
