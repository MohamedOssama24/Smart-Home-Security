package com.shsc.devices;

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
 * Device card (Milestone 20): status per field, user confirmation kept by later scans, custom
 * name never overwritten, identification history (firmware change). [MOCK] data.
 */
class DeviceIdentityTest extends IntegrationTest {

    private static final String TV_MAC = "00:11:22:00:62:10";

    @Autowired
    private Fixtures fixtures;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    @Test
    void cardShowsStatusAndKeepsUserValuesAcrossScans() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa scheda");
        String network = Fixtures.createNetwork(owner, home, "192.168.62.0/24");
        Response auth = owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1"));
        assertThat(auth.status()).as(auth.body()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.9.0", "uptimeSeconds", 5, "interfacesHash", "e".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);

        scan(owner, home, agent, "4.2.1");
        String tv = owner.api().get("/api/v1/homes/" + home + "/devices").json().get(0).get("id").asString();
        JsonNode card = owner.api().get("/api/v1/devices/" + tv).json();
        assertThat(field(card, "MANUFACTURER").get("status").asString()).isEqualTo("VERIFIED");
        assertThat(field(card, "MANUFACTURER").get("sources").toString()).contains("SSDP");
        assertThat(field(card, "FIRMWARE").get("value").asString()).isEqualTo("4.2.1");
        assertThat(field(card, "FIRMWARE").get("status").asString()).isEqualTo("VERIFIED");
        assertThat(field(card, "PRODUCT_CODE").get("value").asString()).isEqualTo("MTV-55");
        assertThat(field(card, "CPE").get("status").asString()).isEqualTo("PROBABLE");
        assertThat(field(card, "OS").get("status").asString()).isEqualTo("UNKNOWN");
        assertThat(card.get("identificationHistory").toString()).contains("FIRMWARE");

        // permissions: read-only users cannot rename or confirm; other organizations see nothing
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        String namePath = "/api/v1/devices/" + tv + "/name";
        String identityPath = "/api/v1/devices/" + tv + "/identity";
        assertThat(reader.api().put(namePath, Map.of("name", "TV")).status()).isEqualTo(403);
        assertThat(reader.api().put(identityPath, Map.of("field", "MODEL", "value", "X")).status()).isEqualTo(403);
        assertThat(accounts().individual().api().put(namePath, Map.of("name", "TV")).status()).isEqualTo(404);
        assertThat(owner.api().put(identityPath, Map.of("field", "IP", "value", "1.2.3.4")).status()).isEqualTo(400);
        assertThat(owner.api().put(identityPath, Map.of("field", "OS", "value", "BEOS")).status()).isEqualTo(400);
        assertThat(owner.api().put(identityPath, Map.of("field", "CPE", "value", "not-a-cpe")).status())
                .isEqualTo(400);

        Response renamed = owner.api().put(namePath, Map.of("name", "  TV soggiorno\u0007 "));
        assertThat(renamed.status()).as(renamed.body()).isEqualTo(200);
        assertThat(renamed.json().get("customName").asString()).isEqualTo("TV soggiorno");
        assertThat(renamed.json().get("displayName").asString()).isEqualTo("TV soggiorno");
        Response confirmed = owner.api().put(identityPath, Map.of("field", "CPE",
                "value", "cpe:2.3:h:mock_vision:mocktv:*:*:*:*:*:*:*:*"));
        assertThat(confirmed.status()).as(confirmed.body()).isEqualTo(200);
        assertThat(field(confirmed.json(), "CPE").get("status").asString()).isEqualTo("VERIFIED");
        assertThat(field(confirmed.json(), "CPE").get("userConfirmed").asBoolean()).isTrue();

        // second scan: new firmware; the name and the confirmed CPE are kept, the change is recorded
        scan(owner, home, agent, "4.3.0");
        JsonNode after = owner.api().get("/api/v1/devices/" + tv).json();
        assertThat(after.get("customName").asString()).isEqualTo("TV soggiorno");
        assertThat(field(after, "FIRMWARE").get("value").asString()).isEqualTo("4.3.0");
        assertThat(field(after, "CPE").get("value").asString()).isEqualTo("cpe:2.3:h:mock_vision:mocktv:*:*:*:*:*:*:*:*");
        assertThat(field(after, "CPE").get("status").asString()).isEqualTo("VERIFIED");
        assertThat(field(after, "CPE").get("conflict").asBoolean()).isTrue(); // the scan derives another CPE
        boolean firmwareChange = false;
        for (JsonNode c : after.get("identificationHistory")) {
            if ("FIRMWARE".equals(c.get("field").asString()) && "4.2.1".equals(c.path("oldValue").asString(null))
                    && "4.3.0".equals(c.get("newValue").asString())) {
                firmwareChange = "SCAN".equals(c.get("origin").asString());
            }
        }
        assertThat(firmwareChange).as(after.get("identificationHistory").toString()).isTrue();
        assertThat(owner.api().get("/api/v1/homes/" + home + "/devices").json().get(0).get("displayName").asString())
                .isEqualTo("TV soggiorno");

        // removing the confirmation: the scanned value applies again
        Map<String, Object> clear = new HashMap<>();
        clear.put("field", "CPE");
        clear.put("value", null);
        Response cleared = owner.api().put(identityPath, clear);
        assertThat(cleared.status()).as(cleared.body()).isEqualTo(200);
        assertThat(field(cleared.json(), "CPE").get("status").asString()).isEqualTo("PROBABLE");
        assertThat(field(cleared.json(), "CPE").get("userConfirmed").asBoolean()).isFalse();
    }

    private void scan(Account owner, String home, EnrolledAgent agent, String firmware) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String base = "/api/v1/agent/scans/" + created.text("id");
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        String now = Instant.now().toString();
        Map<String, Object> arp = new HashMap<>(Map.of("ip", "192.168.62.10", "mac", TV_MAC, "method", "ARP",
                "iface", "eth0", "observedAt", now));
        Map<String, Object> ssdp = new HashMap<>(Map.of("ip", "192.168.62.10", "method", "SSDP", "iface", "eth0",
                "observedAt", now, "details", Map.of("manufacturer", "MOCK Vision Inc.", "modelName", "MockTV",
                        "modelNumber", "MTV-55", "firmwareVersion", firmware)));
        Response results = agents().as(agent).post(base + "/results",
                Map.of("schemaVersion", 1, "batchSeq", 0, "observations", List.of(arp, ssdp)));
        assertThat(results.status()).as(results.body()).isEqualTo(200);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 1,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }

    private static JsonNode field(JsonNode device, String name) {
        for (JsonNode f : device.get("identity")) {
            if (name.equals(f.get("field").asString())) {
                return f;
            }
        }
        throw new AssertionError("field not in card: " + name);
    }
}
