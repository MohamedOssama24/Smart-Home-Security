package com.shsc.integrations;

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
 * Home Assistant inventory uploaded by the agent (Milestone 15, docs/24): validation, scope of
 * the Home Assistant address, idempotency, MAC correlation with the scanned hosts, tenant
 * isolation. The token never reaches the backend. [MOCK] data only.
 */
class HomeAssistantIntegrationTest extends IntegrationTest {

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private static Map<String, Object> device(String name, String protocol, List<String> macs, int entities) {
        Map<String, Object> d = new HashMap<>(Map.of("name", name, "manufacturer", "[MOCK] Acme", "model", "M-1",
                "protocol", protocol, "entities", entities));
        d.put("macs", macs);
        return d;
    }

    private static Map<String, Object> inventory(String ip, List<Map<String, Object>> devices) {
        return Map.of("ip", ip, "version", "2026.11.1", "https", false, "devices", devices,
                "observedAt", Instant.now().toString());
    }

    private Response results(EnrolledAgent agent, String scan, int seq, List<Map<String, Object>> observations,
            Map<String, Object> homeAssistant) {
        Map<String, Object> body = new HashMap<>(Map.of("schemaVersion", 1, "batchSeq", seq,
                "observations", observations));
        if (homeAssistant != null) {
            body.put("homeAssistant", homeAssistant);
        }
        return agents().as(agent).post("/api/v1/agent/scans/" + scan + "/results", body);
    }

    @Test
    void inventoryIsValidatedScopedAndCorrelated() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa Home Assistant");
        String network = Fixtures.createNetwork(owner, home, "192.168.60.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        // online agent; Home Assistant is not a router integration and is not in the capabilities
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.15.0", "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of(),
                        "routerIntegrations", List.of()))).status()).isEqualTo(200);
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agents().as(agent).post("/api/v1/agent/scans/" + scan + "/ack", null).status()).isEqualTo(200);

        // no inventory yet
        assertThat(owner.api().get("/api/v1/scans/" + scan + "/integrations").json().path("homeAssistant").isNull())
                .isTrue();

        // invalid inventories are refused as a whole
        assertThat(results(agent, scan, 0, List.of(), inventory("192.168.60.5",
                List.of(device("bad", "TELNET", List.of(), 1)))).status()).isEqualTo(400);
        assertThat(results(agent, scan, 0, List.of(), inventory("192.168.60.5",
                List.of(device("evil\nname", "ZIGBEE", List.of(), 1)))).status()).isEqualTo(400);
        assertThat(results(agent, scan, 0, List.of(), inventory("192.168.60.5",
                List.of(device("x", "IP", List.of("AA-BB"), 1)))).status()).isEqualTo(400);

        // Home Assistant outside the authorized networks: dropped like any other host
        Response outside = results(agent, scan, 0, List.of(), inventory("10.9.9.9",
                List.of(device("[MOCK] Sensore", "ZIGBEE", List.of(), 2))));
        assertThat(outside.status()).as(outside.body()).isEqualTo(200);
        assertThat(outside.json().get("dropped").asInt()).isEqualTo(1);
        assertThat(owner.api().get("/api/v1/scans/" + scan + "/integrations").json().path("homeAssistant").isNull())
                .isTrue();

        String plugMac = "aa:bb:cc:00:00:61";
        Response hosts = results(agent, scan, 1, List.of(Map.of("ip", "192.168.60.61", "mac", plugMac,
                "method", "ARP", "observedAt", Instant.now().toString())), null);
        assertThat(hosts.status()).as(hosts.body()).isEqualTo(200);
        Response ok = results(agent, scan, 2, List.of(), inventory("192.168.60.5", List.of(
                device("[MOCK] Presa smart", "IP", List.of(plugMac), 3),
                device("[MOCK] Sensore porta", "ZIGBEE", List.of(), 2),
                device("[MOCK] Serratura", "MATTER", List.of(), 1))));
        assertThat(ok.status()).as(ok.body()).isEqualTo(200);
        assertThat(ok.json().get("accepted").asInt()).isEqualTo(1);
        // same batch again: no-op; another batch with an inventory: conflict
        assertThat(results(agent, scan, 2, List.of(), inventory("192.168.60.5", List.of(
                device("[MOCK] Presa smart", "IP", List.of(plugMac), 3),
                device("[MOCK] Sensore porta", "ZIGBEE", List.of(), 2),
                device("[MOCK] Serratura", "MATTER", List.of(), 1)))).json().get("duplicate").asBoolean()).isTrue();
        assertThat(results(agent, scan, 3, List.of(), inventory("192.168.60.5", List.of())).status())
                .isEqualTo(409);

        JsonNode ha = owner.api().get("/api/v1/scans/" + scan + "/integrations").json().get("homeAssistant");
        assertThat(ha.get("ip").asString()).isEqualTo("192.168.60.5");
        assertThat(ha.get("https").asBoolean()).isFalse();
        assertThat(ha.get("deviceCount").asInt()).isEqualTo(3);
        assertThat(ha.get("protocols").toString()).isEqualTo("{\"IP\":1,\"MATTER\":1,\"ZIGBEE\":1}");
        assertThat(ha.get("devices").get(0).get("matchedIp").asString()).isEqualTo("192.168.60.61");
        assertThat(ha.get("devices").get(1).path("matchedIp").isNull()).isTrue();
        assertThat(ha.toString()).doesNotContainIgnoringCase("token");

        // another tenant cannot see it
        Account other = accounts().individual();
        assertThat(other.api().get("/api/v1/scans/" + scan + "/integrations").status()).isEqualTo(404);
    }
}
