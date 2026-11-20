package com.shsc.people;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * Device ↔ person (M24): automatic PROBABLE associations from device names, confirmation,
 * removal never proposed again, deleted automatic people not created again, permissions and
 * tenant isolation. [MOCK] data.
 */
class DevicePeopleTest extends IntegrationTest {

    private static final String PHONE = "00:11:22:00:63:10";
    private static final String MAC = "00:11:22:00:63:20";
    private static final String PC = "00:11:22:00:63:30";

    @Autowired
    private Fixtures fixtures;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private static Map<String, Object> obs(String ip, String mac, String method, String hostname) {
        Map<String, Object> o = new HashMap<>(Map.of("ip", ip, "method", method, "observedAt", Instant.now().toString()));
        if (mac != null) {
            o.put("mac", mac);
        }
        if (hostname != null) {
            o.put("hostname", hostname);
        }
        return o;
    }

    private void scan(Account owner, String home, EnrolledAgent agent) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String base = "/api/v1/agent/scans/" + created.text("id");
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", List.of(
                        obs("192.168.63.10", PHONE, "ARP", null),
                        obs("192.168.63.10", null, "TR064", "iPhone-di-Marco"),
                        obs("192.168.63.20", MAC, "ARP", null),
                        obs("192.168.63.20", null, "TR064", "Giulias-MacBook-Pro"),
                        obs("192.168.63.30", PC, "ARP", null),
                        obs("192.168.63.30", null, "NETBIOS", "DESKTOP-AB12CD3")))).status()).isEqualTo(200);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 1,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }

    @Test
    void devicesNameTheirPeopleAndTheUserDecides() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa persone");
        String network = Fixtures.createNetwork(owner, home, "192.168.63.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.8.0", "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of(),
                        "routerIntegrations", List.of("TR064")))).status()).isEqualTo(200);
        scan(owner, home, agent);

        JsonNode devices = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        String phone = id(devices, PHONE), mac = id(devices, MAC), pc = id(devices, PC);
        JsonNode people = owner.api().get("/api/v1/homes/" + home + "/people").json();
        assertThat(people.size()).as(people.toString()).isEqualTo(2); // the Windows default name gives nobody
        JsonNode marco = person(people, "Marco");
        assertThat(marco.get("origin").asString()).isEqualTo("DEVICE_NAME");
        assertThat(marco.get("devices").size()).isEqualTo(1);
        JsonNode link = marco.get("devices").get(0);
        assertThat(link.get("deviceId").asString()).isEqualTo(phone);
        assertThat(link.get("status").asString()).isEqualTo("PROBABLE");
        assertThat(link.get("evidence").asString()).isEqualTo("iPhone-di-Marco");
        String giulia = person(people, "Giulia").get("id").asString();
        assertThat(person(people, "Giulia").get("devices").get(0).get("deviceId").asString()).isEqualTo(mac);

        // the user: removes Marco from the phone, deletes Giulia, creates Luca and assigns the PC to him
        String marcoId = marco.get("id").asString();
        Response removed = owner.api().delete("/api/v1/devices/" + phone + "/people/" + marcoId);
        assertThat(removed.status()).as(removed.body()).isEqualTo(200);
        assertThat(removed.json().get("devices").size()).isZero();
        assertThat(owner.api().delete("/api/v1/people/" + giulia).status()).isEqualTo(204);
        Response luca = owner.api().post("/api/v1/homes/" + home + "/people", Map.of("name", " Luca "));
        assertThat(luca.status()).as(luca.body()).isEqualTo(201);
        assertThat(luca.json().get("name").asString()).isEqualTo("Luca");
        assertThat(owner.api().post("/api/v1/homes/" + home + "/people", Map.of("name", "luca")).status())
                .isEqualTo(409);
        String lucaId = luca.text("id");
        Response assigned = owner.api().put("/api/v1/devices/" + pc + "/people/" + lucaId, null);
        assertThat(assigned.status()).as(assigned.body()).isEqualTo(200);
        assertThat(assigned.json().get("devices").get(0).get("status").asString()).isEqualTo("CONFIRMED");
        assertThat(assigned.json().get("devices").get(0).get("source").asString()).isEqualTo("USER");

        // the next scan proposes neither the removed association nor the deleted person
        scan(owner, home, agent);
        JsonNode after = owner.api().get("/api/v1/homes/" + home + "/people").json();
        assertThat(after.size()).as(after.toString()).isEqualTo(2);
        assertThat(person(after, "Marco").get("devices").size()).isZero();
        assertThat(person(after, "Luca").get("devices").get(0).get("status").asString()).isEqualTo("CONFIRMED");
        assertThat(after.toString()).doesNotContain("Giulia");

        // a read-only user sees neither people nor associations; another tenant sees nothing
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(reader.api().get("/api/v1/homes/" + home + "/people").status()).isEqualTo(403);
        assertThat(reader.api().put("/api/v1/devices/" + pc + "/people/" + lucaId, null).status()).isEqualTo(403);
        Account stranger = accounts().individual();
        assertThat(stranger.api().get("/api/v1/homes/" + home + "/people").status()).isEqualTo(404);
        assertThat(stranger.api().delete("/api/v1/people/" + lucaId).status()).isEqualTo(404);
        assertThat(stranger.api().put("/api/v1/devices/" + pc + "/people/" + lucaId, null).status()).isEqualTo(404);
        String otherHome = Fixtures.createHome(stranger, "Altra casa");
        assertThat(stranger.api().get("/api/v1/homes/" + otherHome + "/people").json().size()).isZero();

        // deleting a person removes its associations
        assertThat(owner.api().delete("/api/v1/people/" + lucaId).status()).isEqualTo(204);
        assertThat(owner.api().get("/api/v1/homes/" + home + "/people").json().toString()).doesNotContain(pc);
    }

    private static String id(JsonNode devices, String mac) {
        for (JsonNode d : devices) {
            if (mac.equals(d.path("mac").asString(null))) {
                return d.get("id").asString();
            }
        }
        throw new AssertionError("device not found: " + mac);
    }

    private static JsonNode person(JsonNode people, String name) {
        for (JsonNode p : people) {
            if (name.equals(p.get("name").asString())) {
                return p;
            }
        }
        throw new AssertionError("person not found: " + name + " in " + people);
    }
}
