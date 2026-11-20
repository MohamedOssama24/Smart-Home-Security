package com.shsc.scans;

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

/** Deletion of one scan and of the inventory of a home (ADR-082). [MOCK] data. */
class ScanDeletionTest extends IntegrationTest {

    private static final String PHONE = "00:11:22:00:64:10";
    private static final String PC = "00:11:22:00:64:20";
    private static final String GUEST = "00:11:22:00:64:30";

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

    private String scan(Account owner, String home, EnrolledAgent agent, List<Map<String, Object>> observations) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String id = created.text("id");
        String base = "/api/v1/agent/scans/" + id;
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", observations)).status()).isEqualTo(200);
        assertThat(agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 1,
                "outcome", "COMPLETED", "warnings", List.of())).status()).isEqualTo(200);
        return id;
    }

    @Test
    void deletingAScanKeepsTheInventoryConsistentAndClearingAHomeStartsOver() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa cancellazioni");
        String network = Fixtures.createNetwork(owner, home, "192.168.64.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.8.0", "uptimeSeconds", 5, "interfacesHash", "d".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of(),
                        "routerIntegrations", List.of("TR064")))).status()).isEqualTo(200);

        String first = scan(owner, home, agent, List.of(
                obs("192.168.64.10", PHONE, "ARP", null),
                obs("192.168.64.10", null, "TR064", "iPhone-di-Marco"),
                obs("192.168.64.20", PC, "ARP", null)));
        String second = scan(owner, home, agent, List.of(
                obs("192.168.64.10", PHONE, "ARP", null),
                obs("192.168.64.30", GUEST, "ARP", null)));
        assertThat(owner.api().get("/api/v1/homes/" + home + "/devices").json().size()).isEqualTo(3);

        // permissions: read-only 403, another tenant 404
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(reader.api().delete("/api/v1/scans/" + second).status()).isEqualTo(403);
        assertThat(reader.api().delete("/api/v1/homes/" + home + "/inventory").status()).isEqualTo(403);
        Account stranger = accounts().individual();
        assertThat(stranger.api().delete("/api/v1/scans/" + second).status()).isEqualTo(404);
        assertThat(stranger.api().delete("/api/v1/homes/" + home + "/inventory").status()).isEqualTo(404);

        // deleting the second scan: the guest (seen only there) goes, the phone goes back to the first scan
        Response deleted = owner.api().delete("/api/v1/scans/" + second);
        assertThat(deleted.status()).as(deleted.body()).isEqualTo(200);
        assertThat(deleted.json().get("devices").asInt()).isEqualTo(1);
        assertThat(owner.api().get("/api/v1/scans/" + second).status()).isEqualTo(404);
        JsonNode devices = owner.api().get("/api/v1/homes/" + home + "/devices").json();
        assertThat(devices.size()).as(devices.toString()).isEqualTo(2);
        for (JsonNode d : devices) {
            assertThat(d.get("lastScanId").asString()).isEqualTo(first);
            assertThat(d.get("mac").asString()).isNotEqualTo(GUEST);
        }
        assertThat(owner.api().get("/api/v1/homes/" + home + "/scans").json().size()).isEqualTo(1);

        // a scan still to run cannot be deleted; once cancelled it can
        Response pending = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        String third = pending.text("id");
        Response active = owner.api().delete("/api/v1/scans/" + third);
        assertThat(active.status()).isEqualTo(409);
        assertThat(active.body()).contains("SCAN_ACTIVE");
        assertThat(owner.api().delete("/api/v1/homes/" + home + "/inventory").status()).isEqualTo(409);
        assertThat(owner.api().post("/api/v1/scans/" + third + "/cancel", null).status()).isEqualTo(202);
        assertThat(owner.api().delete("/api/v1/scans/" + third).status()).isEqualTo(200);

        // clearing the home: no scan, device or person left; the home stays
        assertThat(owner.api().get("/api/v1/homes/" + home + "/people").json().size()).isEqualTo(1);
        Response cleared = owner.api().delete("/api/v1/homes/" + home + "/inventory");
        assertThat(cleared.status()).as(cleared.body()).isEqualTo(200);
        assertThat(cleared.json().get("scans").asInt()).isEqualTo(1);
        assertThat(cleared.json().get("devices").asInt()).isEqualTo(2);
        assertThat(owner.api().get("/api/v1/homes/" + home + "/devices").json().size()).isZero();
        assertThat(owner.api().get("/api/v1/homes/" + home + "/scans").json().size()).isZero();
        assertThat(owner.api().get("/api/v1/homes/" + home + "/people").json().size()).isZero();
        assertThat(owner.api().get("/api/v1/homes/" + home).status()).isEqualTo(200);
    }
}
