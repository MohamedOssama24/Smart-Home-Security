package com.shsc.scans;

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
 * Network discovery results (Milestone 7): the new methods with host names and details, IPv6
 * targets, grouping of the addresses of one device, name reliability order, validation of what
 * the agent uploads, router integrations reported by the agent capabilities. [MOCK] data only.
 */
class NetworkDiscoveryTest extends IntegrationTest {

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private static void authorize(Account owner, String network) {
        Response r = owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1"));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
    }

    private Response heartbeat(EnrolledAgent agent, Object routerIntegrations) {
        Map<String, Object> caps = new HashMap<>(Map.of("privileged", false, "arp", "os_api", "icmp", "os_api",
                "warnings", List.of()));
        caps.put("routerIntegrations", routerIntegrations);
        return agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1, "agentVersion", "0.7.0",
                "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0, "capabilities", caps));
    }

    private static Map<String, Object> obs(String ip, String mac, String method, String hostname,
            Map<String, Object> details) {
        Map<String, Object> o = new HashMap<>(Map.of("ip", ip, "method", method, "observedAt", Instant.now().toString()));
        if (mac != null) {
            o.put("mac", mac);
        }
        if (hostname != null) {
            o.put("hostname", hostname);
        }
        if (details != null) {
            o.put("details", details);
        }
        return o;
    }

    private Response results(EnrolledAgent agent, String scan, int seq, List<Map<String, Object>> observations) {
        return agents().as(agent).post("/api/v1/agent/scans/" + scan + "/results",
                Map.of("schemaVersion", 1, "batchSeq", seq, "observations", observations));
    }

    @Test
    void discoveryResultsAreValidatedGroupedAndNamedByReliability() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa discovery");
        authorize(owner, Fixtures.createNetwork(owner, home, "192.168.50.0/24"));
        authorize(owner, Fixtures.createNetwork(owner, home, "fd00:50::/64"));
        EnrolledAgent agent = agents().enroll(owner, home);

        // router integrations: names only; anything else is refused
        assertThat(heartbeat(agent, List.of("TR064", "SNMP")).status()).isEqualTo(200);
        assertThat(heartbeat(agent, List.of("TELNET")).status()).isEqualTo(400);

        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agents().as(agent).post("/api/v1/agent/scans/" + scan + "/ack", null).status()).isEqualTo(200);

        // invalid uploads are refused as a whole and nothing is stored
        assertThat(results(agent, scan, 0, List.of(obs("192.168.50.9", null, "EXPLOIT", null, null))).status())
                .isEqualTo(400);
        assertThat(results(agent, scan, 0, List.of(obs("192.168.50.9", null, "MDNS", "evil\nname", null))).status())
                .isEqualTo(400);
        Response tooLarge = results(agent, scan, 0,
                List.of(obs("192.168.50.9", null, "SSDP", null, Map.of("server", "x".repeat(4000)))));
        assertThat(tooLarge.status()).isEqualTo(400);
        assertThat(tooLarge.body()).contains("DETAILS_TOO_LARGE");

        String mac = "aa:bb:cc:00:00:20";
        Response ok = results(agent, scan, 0, List.of(
                obs("192.168.50.20", mac, "ARP", null, null),
                obs("192.168.50.20", null, "ICMP", null, Map.of("ttl", 64)),
                obs("192.168.50.20", null, "RDNS", "host-20.lan", null),
                obs("192.168.50.20", null, "NETBIOS", "MOCK-NAS", Map.of("workgroup", "WORKGROUP")),
                obs("192.168.50.20", null, "MDNS", "mock-nas", Map.of("selfDeclared", true,
                        "services", List.of(Map.of("type", "_smb._tcp", "port", 445)))),
                obs("fd00:50::20", mac, "NDP", null, null),
                obs("192.168.50.1", null, "UPNP_IGD", null, Map.of("selfDeclared", true, "externalIp", "198.51.100.7",
                        "portMappings", List.of(Map.of("protocol", "TCP", "externalPort", 8080,
                                "internalClient", "192.168.50.20", "internalPort", 80, "enabled", true)))),
                obs("192.168.50.30", "aa:bb:cc:00:00:30", "TR064", "MOCK-TV", Map.of("source", "router")),
                obs("192.168.50.30", null, "MDNS", "living-room-tv", null),
                obs("fd00:99::1", null, "NDP", null, null))); // outside the authorized targets
        assertThat(ok.status()).as(ok.body()).isEqualTo(200);
        assertThat(ok.json().get("accepted").asInt()).isEqualTo(9);
        assertThat(ok.json().get("dropped").asInt()).isEqualTo(1);

        JsonNode devices = owner.api().get("/api/v1/scans/" + scan + "/devices").json();
        assertThat(devices.size()).isEqualTo(3);
        JsonNode nas = find(devices, mac);
        assertThat(nas.get("ip").asString()).isEqualTo("192.168.50.20");
        assertThat(nas.get("addresses").toString()).isEqualTo("[\"192.168.50.20\",\"fd00:50::20\"]");
        assertThat(nas.get("methods").toString()).contains("ARP", "ICMP", "MDNS", "NDP", "NETBIOS", "RDNS");
        assertThat(nas.get("hostname").asString()).isEqualTo("mock-nas"); // mDNS before NetBIOS and rDNS
        assertThat(nas.get("hostnames").size()).isEqualTo(2); // MOCK-NAS and mock-nas are the same name
        assertThat(nas.get("evidence").toString()).contains("\"selfDeclared\":true", "_smb._tcp", "\"ttl\":64");
        assertThat(find(devices, "aa:bb:cc:00:00:30").get("hostname").asString()).isEqualTo("MOCK-TV"); // router table
        JsonNode gateway = find(devices, "192.168.50.1");
        assertThat(gateway.get("mac").isNull()).isTrue();
        assertThat(gateway.get("evidence").get(0).get("details").get("portMappings").get(0).get("externalPort").asInt())
                .isEqualTo(8080);
        assertThat(devices.toString()).doesNotContain("fd00:99::1");
    }

    private static JsonNode find(JsonNode devices, String macOrIp) {
        for (JsonNode d : devices) {
            if (macOrIp.equals(d.path("mac").asString(null)) || macOrIp.equals(d.get("ip").asString())) {
                return d;
            }
        }
        throw new AssertionError("device not found: " + macOrIp);
    }
}
