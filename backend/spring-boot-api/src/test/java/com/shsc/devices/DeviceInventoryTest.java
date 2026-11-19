package com.shsc.devices;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.devices.oui.OuiRegistryParser.Entry;
import com.shsc.devices.oui.OuiRepository;
import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * Device inventory (Milestone 8): fingerprinting at scan completion, per-field confidence,
 * randomized MACs, manual classification with history, kept across later scans. [MOCK] data.
 */
class DeviceInventoryTest extends IntegrationTest {

    private static final String PRINTER = "00:11:22:00:60:10";
    private static final String ROUTER = "00:11:22:00:60:01";
    private static final String CAMERA = "44:19:b6:00:60:20";
    private static final String PHONE = "da:a1:19:00:60:30";
    private static final String PC = "00:11:22:00:60:40";

    @Autowired
    private Fixtures fixtures;

    @Autowired
    private OuiRepository oui;

    @Autowired
    private TransactionTemplate tx;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
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

    private void scan(Account owner, String home, EnrolledAgent agent, List<Map<String, Object>> observations) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        String base = "/api/v1/agent/scans/" + scan;
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        Response results = agents().as(agent).post(base + "/results",
                Map.of("schemaVersion", 1, "batchSeq", 0, "observations", observations));
        assertThat(results.status()).as(results.body()).isEqualTo(200);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 1,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }

    private static List<Map<String, Object>> firstScan() {
        return List.of(
                obs("192.168.60.10", PRINTER, "ARP", null, null),
                obs("192.168.60.10", null, "MDNS", "mock-printer", Map.of("selfDeclared", true,
                        "services", List.of(Map.of("type", "_ipp._tcp", "port", 631)))),
                obs("192.168.60.10", null, "SSDP", null, Map.of("deviceType", "urn:schemas-upnp-org:device:Printer:1",
                        "manufacturer", "MOCK Printers")),
                obs("192.168.60.1", ROUTER, "ARP", null, null),
                obs("192.168.60.1", null, "TR064", "mock-router", Map.of("router", true)),
                obs("192.168.60.1", null, "UPNP_IGD", null, Map.of("selfDeclared", true)),
                obs("192.168.60.20", CAMERA, "ARP", null, null),
                obs("192.168.60.20", null, "RDNS", "camera-20.lan", null),
                obs("192.168.60.30", PHONE, "ARP", null, null),
                obs("192.168.60.30", null, "TR064", "Mock-Phone", Map.of("source", "router")),
                obs("192.168.60.40", PC, "ARP", null, null),
                obs("192.168.60.40", null, "ICMP", null, Map.of("ttl", 128)),
                obs("192.168.60.40", null, "NETBIOS", "DESKTOP-AB12CD3", Map.of("workgroup", "WORKGROUP")));
    }

    @Test
    void scansBuildAClassifiedInventoryThatKeepsManualChoices() throws Exception {
        // MOCK registry: the camera maker, and a prefix equal to the randomized MAC (must be ignored)
        tx.executeWithoutResult(s -> oui.replace("MA-L", List.of(
                new Entry("4419B6", 24, "MOCK Hikvision Digital Technology", "MA-L"),
                new Entry("DAA119", 24, "MOCK Should Not Be Used", "MA-L")), Instant.now()));

        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa inventario");
        String network = Fixtures.createNetwork(owner, home, "192.168.60.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.8.0", "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of(),
                        "routerIntegrations", List.of("TR064"))));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);
        scan(owner, home, agent, firstScan());

        JsonNode list = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        assertThat(list.size()).isEqualTo(5);

        JsonNode printer = find(list, PRINTER);
        assertThat(printer.get("category").asString()).isEqualTo("PRINTER");
        assertThat(printer.get("detectedCategoryConfidence").asString()).isEqualTo("HIGH");
        assertThat(printer.get("rulesetVersion").asString()).isNotBlank();
        assertThat(printer.get("classification").toString()).contains("printer.mdns-ipp", "printer.ssdp-type");

        JsonNode router = find(list, ROUTER);
        assertThat(router.get("category").asString()).isEqualTo("ROUTER");
        assertThat(router.get("detectedCategoryConfidence").asString()).isEqualTo("HIGH");

        // weak hints only (maker of the network card + name): not classified, but explained
        JsonNode camera = find(list, CAMERA);
        assertThat(camera.get("category").asString()).isEqualTo("UNKNOWN_DEVICE");
        assertThat(camera.get("detectedCategoryConfidence").isNull()).isTrue();
        assertThat(camera.get("manufacturer").asString()).isEqualTo("MOCK Hikvision Digital Technology");
        assertThat(camera.get("classification").toString()).contains("camera.oui", "camera.hostname");

        // randomized MAC: recognized, the registry is not consulted
        JsonNode phone = find(list, PHONE);
        assertThat(phone.get("macRandomized").asBoolean()).isTrue();
        assertThat(phone.get("manufacturer").isNull()).isTrue();
        assertThat(phone.get("hostname").asString()).isEqualTo("Mock-Phone");

        JsonNode pc = owner.api().get("/api/v1/devices/" + find(list, PC).get("id").asString()).json();
        assertThat(pc.get("os").asString()).isEqualTo("WINDOWS");
        JsonNode os = field(pc, "OS");
        assertThat(os.get("confidence").asString()).isEqualTo("MEDIUM");
        assertThat(os.get("sources").toString()).contains("NETBIOS", "TTL");
        assertThat(field(pc, "MAC").get("confidence").asString()).isEqualTo("HIGH");

        // manual classification: validated, audited in the history, effective immediately
        String printerId = printer.get("id").asString();
        String path = "/api/v1/devices/" + printerId + "/category";
        assertThat(owner.api().put(path, Map.of("category", "TOASTER")).status()).isEqualTo(400);
        Response manual = owner.api().put(path, Map.of("category", "NAS"));
        assertThat(manual.status()).as(manual.body()).isEqualTo(200);
        assertThat(manual.json().get("category").asString()).isEqualTo("NAS");
        assertThat(manual.json().get("detectedCategory").asString()).isEqualTo("PRINTER");
        assertThat(manual.json().get("suggestedCategory").asString()).isEqualTo("PRINTER");
        JsonNode history = manual.json().get("categoryHistory");
        assertThat(history.get(0).get("source").asString()).isEqualTo("MANUAL");
        assertThat(history.get(0).get("newCategory").asString()).isEqualTo("NAS");
        assertThat(history.get(0).get("changedBy").asString()).isEqualTo(owner.userId().toString());
        assertThat(history.toString()).contains("\"source\":\"AUTO\"");

        // a read-only user sees the inventory but cannot classify; other organizations see nothing
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(reader.api().get("/api/v1/devices/" + printerId).status()).isEqualTo(200);
        assertThat(reader.api().put(path, Map.of("category", "PRINTER")).status()).isEqualTo(403);
        Account stranger = accounts().individual();
        assertThat(stranger.api().get("/api/v1/devices/" + printerId).status()).isEqualTo(404);
        assertThat(stranger.api().put(path, Map.of("category", "PRINTER")).status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/homes/" + home + "/devices").status()).isEqualTo(404);

        // second scan: the manual choice is kept, the device is the same, a new randomized MAC
        // with the same name is linked as "probably the same device"
        String newPhoneMac = "da:a1:19:00:60:99";
        List<Map<String, Object>> second = new java.util.ArrayList<>(firstScan());
        second.add(obs("192.168.60.31", newPhoneMac, "ARP", null, null));
        second.add(obs("192.168.60.31", null, "TR064", "Mock-Phone", Map.of("source", "router")));
        scan(owner, home, agent, second);

        JsonNode after = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        assertThat(after.size()).isEqualTo(6);
        JsonNode kept = owner.api().get("/api/v1/devices/" + printerId).json();
        assertThat(kept.get("category").asString()).isEqualTo("NAS");
        assertThat(kept.get("suggestedCategory").asString()).isEqualTo("PRINTER");
        assertThat(kept.get("categoryHistory").size()).isEqualTo(2); // no new AUTO entry: detection unchanged
        assertThat(kept.get("lastScanId").asString()).isNotEqualTo(printer.get("lastScanId").asString());
        assertThat(find(after, newPhoneMac).get("probableSameAs").asString()).isEqualTo(phone.get("id").asString());

        // clearing the manual category goes back to the detected one
        Response cleared = owner.api().put(path, new HashMap<>(Map.of()));
        assertThat(cleared.status()).as(cleared.body()).isEqualTo(200);
        assertThat(cleared.json().get("category").asString()).isEqualTo("PRINTER");
        assertThat(cleared.json().get("suggestedCategory").isNull()).isTrue();
    }

    private static JsonNode field(JsonNode device, String name) {
        for (JsonNode i : device.get("identifications")) {
            if (name.equals(i.get("field").asString())) {
                return i;
            }
        }
        throw new AssertionError("field not identified: " + name);
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
