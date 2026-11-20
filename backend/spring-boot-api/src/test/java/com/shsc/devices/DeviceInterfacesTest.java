package com.shsc.devices;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
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
 * Complete inventory (Milestone 19): interfaces, IPv4/IPv6 address history, EUI-64 grouping,
 * "probably the same device" confirmed (merge) or dismissed by the user. [MOCK] data.
 */
class DeviceInterfacesTest extends IntegrationTest {

    private static final String PC_ETH = "00:11:22:00:61:10";
    private static final String PC_WIFI = "00:11:22:00:61:11";
    private static final String OTHER = "00:11:22:00:61:30";
    /** EUI-64 address of PC_ETH, seen without MAC. */
    private static final String PC_EUI64 = "fd00:61::211:22ff:fe00:6110";
    /** Global address of the PC (documentation range, MOCK), never inside an authorized network. */
    private static final String GLOBAL_V6 = "2001:db8:61::10";

    @Autowired
    private Fixtures fixtures;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    @Test
    void inventoryKeepsInterfacesAndAddressHistoryAndMergesOnlyOnConfirmation() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa interfacce");
        for (String cidr : List.of("192.168.61.0/24", "fd00:61::/64")) {
            String network = Fixtures.createNetwork(owner, home, cidr);
            Response auth = owner.api().post("/api/v1/networks/" + network + "/authorization",
                    Map.of("attestation", true, "attestationVersion", "1"));
            assertThat(auth.status()).as(auth.body()).isEqualTo(200);
        }
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.8.0", "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);

        // scan 1: dual-stack PC (IPv4, IPv6 with MAC, EUI-64 IPv6 without MAC), its Wi-Fi card and a
        // third device announcing the same name
        List<Map<String, Object>> first = new ArrayList<>(List.of(
                obs("192.168.61.10", PC_ETH, "ARP", null),
                obs("192.168.61.10", null, "MDNS", "mock-pc"),
                obs("fd00:61::10", PC_ETH, "NDP", null),
                obs(PC_EUI64, null, "ICMP", null),
                obs("192.168.61.11", PC_WIFI, "ARP", null),
                obs("192.168.61.11", null, "MDNS", "mock-pc"),
                obs("192.168.61.30", OTHER, "ARP", null),
                obs("192.168.61.30", null, "MDNS", "mock-pc")));
        // global IPv6 read passively from the neighbour table: only valid global literals are kept,
        // and a global address sent as an observation of its own is outside the scan and dropped
        Map<String, Object> ndp = new HashMap<>(first.get(2)); // same observedAt: the PC stays the oldest device
        ndp.put("details", Map.of("globalIpv6", List.of(GLOBAL_V6, "fd00:61::99", "8.8.8.8", "not-an-ip")));
        first.set(2, ndp);
        first.add(obs("2001:db8:61::99", OTHER, "NDP", null));
        scan(owner, home, agent, first);
        first.remove(first.size() - 1);

        JsonNode list = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        assertThat(list.size()).isEqualTo(3); // the EUI-64 address joined the PC, no device of its own
        String pc = find(list, PC_ETH).get("id").asString();
        String wifi = find(list, PC_WIFI).get("id").asString();
        String other = find(list, OTHER).get("id").asString();
        assertThat(find(list, PC_WIFI).get("probableSameAs").asString()).isEqualTo(pc);
        assertThat(find(list, OTHER).get("probableSameAs").asString()).isEqualTo(pc);
        assertThat(find(list, PC_ETH).get("probableSameAs").isNull()).isTrue(); // the oldest one is the reference

        JsonNode detail = owner.api().get("/api/v1/devices/" + pc).json();
        JsonNode interfaces = detail.get("interfaces");
        assertThat(interfaces.size()).isEqualTo(1);
        assertThat(interfaces.get(0).get("mac").asString()).isEqualTo(PC_ETH);
        assertThat(interfaces.get(0).get("agentInterface").asString()).isEqualTo("eth0");
        assertThat(interfaces.get(0).get("current").asBoolean()).isTrue();
        JsonNode eui = address(detail, PC_EUI64);
        assertThat(eui.get("family").asInt()).isEqualTo(6);
        assertThat(eui.get("scope").asString()).isEqualTo("UNIQUE_LOCAL");
        assertThat(eui.get("interfaceId").asString()).isEqualTo("EUI64");
        assertThat(eui.get("eui64Mac").asString()).isEqualTo(PC_ETH);
        assertThat(eui.get("mac").asString()).isEqualTo(PC_ETH);
        assertThat(address(detail, "192.168.61.10").get("scope").asString()).isEqualTo("PRIVATE");
        assertThat(address(detail, "fd00:61::10").get("current").asBoolean()).isTrue();
        JsonNode global = address(detail, GLOBAL_V6);
        assertThat(global.get("scope").asString()).isEqualTo("GLOBAL");
        assertThat(global.get("mac").asString()).isEqualTo(PC_ETH);
        assertThat(detail.get("addressHistory").toString()).doesNotContain("fd00:61::99", "8.8.8.8",
                "2001:db8:61::99");
        assertThat(detail.get("addresses").toString()).doesNotContain(GLOBAL_V6); // recorded, never a target
        assertThat(detail.get("ip").asString()).isNotEqualTo(GLOBAL_V6);

        // merging needs device:classify on the home; other organizations see nothing
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        String mergePath = "/api/v1/devices/" + wifi + "/merge";
        assertThat(reader.api().post(mergePath, Map.of("intoDeviceId", pc)).status()).isEqualTo(403);
        assertThat(accounts().individual().api().post(mergePath, Map.of("intoDeviceId", pc)).status()).isEqualTo(404);
        assertThat(owner.api().post(mergePath, Map.of("intoDeviceId", wifi)).status()).isEqualTo(400);

        // the user confirms: the Wi-Fi card becomes a second interface of the PC
        Response merged = owner.api().post(mergePath, Map.of("intoDeviceId", pc));
        assertThat(merged.status()).as(merged.body()).isEqualTo(200);
        assertThat(merged.json().get("interfaces").size()).isEqualTo(2);
        assertThat(merged.json().get("interfaces").toString()).contains(PC_ETH, PC_WIFI);
        assertThat(address(merged.json(), "192.168.61.11").get("mac").asString()).isEqualTo(PC_WIFI);
        assertThat(owner.api().get("/api/v1/devices/" + wifi).status()).isEqualTo(404);

        // "not the same device": the hint disappears and does not come back with later scans
        Response dismissed = owner.api().post("/api/v1/devices/" + other + "/same-as/dismiss",
                Map.of("otherDeviceId", pc));
        assertThat(dismissed.status()).as(dismissed.body()).isEqualTo(200);
        assertThat(dismissed.json().get("probableSameAs").isNull()).isTrue();

        // scan 2: the PC changes IPv4 address; the Wi-Fi MAC is recognized as an interface of the PC
        List<Map<String, Object>> second = new ArrayList<>(first);
        second.set(0, obs("192.168.61.20", PC_ETH, "ARP", null));
        second.set(1, obs("192.168.61.20", null, "MDNS", "mock-pc"));
        scan(owner, home, agent, second);

        assertThat(owner.api().get("/api/v1/homes/" + home + "/devices").json().size()).isEqualTo(2);
        JsonNode afterMove = owner.api().get("/api/v1/devices/" + pc).json();
        assertThat(address(afterMove, "192.168.61.10").get("current").asBoolean()).isFalse();
        assertThat(address(afterMove, "192.168.61.20").get("current").asBoolean()).isTrue();
        assertThat(address(afterMove, "fd00:61::10").get("timesSeen").asInt()).isEqualTo(2);
        assertThat(afterMove.get("addressHistory").size()).isEqualTo(6); // .10 .11 .20 and three IPv6
        for (JsonNode i : afterMove.get("interfaces")) {
            assertThat(i.get("current").asBoolean()).as(i.toString()).isTrue();
        }
        assertThat(owner.api().get("/api/v1/devices/" + other).json().get("probableSameAs").isNull()).isTrue();
    }

    private void scan(Account owner, String home, EnrolledAgent agent, List<Map<String, Object>> observations) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String base = "/api/v1/agent/scans/" + created.text("id");
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        Response results = agents().as(agent).post(base + "/results",
                Map.of("schemaVersion", 1, "batchSeq", 0, "observations", observations));
        assertThat(results.status()).as(results.body()).isEqualTo(200);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 1,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }

    private static Map<String, Object> obs(String ip, String mac, String method, String hostname) {
        Map<String, Object> o = new HashMap<>(Map.of("ip", ip, "method", method, "iface", "eth0",
                "observedAt", Instant.now().toString()));
        if (mac != null) {
            o.put("mac", mac);
        }
        if (hostname != null) {
            o.put("hostname", hostname);
        }
        return o;
    }

    private static JsonNode address(JsonNode device, String address) {
        for (JsonNode a : device.get("addressHistory")) {
            if (address.equals(a.get("address").asString())) {
                return a;
            }
        }
        throw new AssertionError("address not in history: " + address + " in " + device.get("addressHistory"));
    }

    private static JsonNode find(JsonNode devices, String mac) {
        for (JsonNode d : devices) {
            if (mac.equals(d.path("mac").asString(null))) {
                return d;
            }
        }
        throw new AssertionError("device not found: " + mac);
    }
}
