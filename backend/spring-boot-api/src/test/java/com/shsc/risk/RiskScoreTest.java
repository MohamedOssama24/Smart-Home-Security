package com.shsc.risk;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;
import com.shsc.vulnintel.VulnerabilityRepository;
import com.shsc.vulnintel.VulnerabilityRepository.CpeMatch;
import com.shsc.vulnintel.VulnerabilityRepository.Cve;

import tools.jackson.databind.JsonNode;

/**
 * Risk snapshots (Milestone 11): score and coverage at scan completion, breakdown, delta with its
 * reasons, recomputation after a triage, no score after a DISCOVERY scan, history, CVEs of the
 * home and tenant isolation. [MOCK] device and CVE (CVE-2099-*): nothing is scanned.
 */
class RiskScoreTest extends IntegrationTest {

    private static final String LAN = "192.168.72.0/24";
    private static final String IP = "192.168.72.20";
    private static final String MAC = "00:11:22:00:72:20";

    @Autowired
    private VulnerabilityRepository vulnerabilities;

    @Autowired
    private TransactionTemplate tx;

    private record Ready(Account owner, String home, EnrolledAgent agent) {
    }

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private Ready ready() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa rischio");
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.11.0", "uptimeSeconds", 5, "interfacesHash", "f".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);
        return new Ready(owner, home, agent);
    }

    private Response agentPost(Ready r, String scan, String op, Object body) {
        return agents().as(r.agent()).post("/api/v1/agent/scans/" + scan + "/" + op, body);
    }

    private static Map<String, Object> port(int port, String name, String product, String version) {
        Map<String, Object> service = new HashMap<>(Map.of("name", name, "status", "CONFIRMED", "confidence", "HIGH"));
        if (product != null) {
            service.put("product", product);
            service.put("version", version);
            service.put("evidence", Map.of("banner", "SSH-2.0-MOCK"));
        }
        return Map.of("ip", IP, "protocol", "TCP", "port", port, "state", "OPEN", "reason", "syn-ack",
                "observedAt", Instant.now().toString(), "service", service);
    }

    /** One complete scan of the [MOCK] device; DISCOVERY sends no port data. */
    private String scan(Ready r, String profile, List<Map<String, Object>> ports, List<String> warnings) {
        Response created = r.owner().api().post("/api/v1/homes/" + r.home() + "/scans", Map.of("profile", profile));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agentPost(r, scan, "ack", null).status()).isEqualTo(200);
        boolean portScan = !"DISCOVERY".equals(profile);
        List<Map<String, Object>> observations = portScan
                ? List.of(Map.of("ip", IP, "mac", MAC, "method", "ARP", "observedAt", Instant.now().toString()),
                        Map.of("ip", IP, "method", "PORTSCAN", "observedAt", Instant.now().toString(), "details",
                                Map.of("profile", profile, "listVersion", "2026.11-1",
                                        "tcp", Map.of("probed", 40, "open", ports.size(), "closed", 40 - ports.size(),
                                                "filtered", 0, "openFiltered", 0, "unknown", 0),
                                        "udp", Map.of("probed", 0, "open", 0, "closed", 0, "filtered", 0,
                                                "openFiltered", 0, "unknown", 0),
                                        "paused", false)))
                : List.of(Map.of("ip", IP, "mac", MAC, "method", "ARP", "observedAt", Instant.now().toString()));
        Response hosts = agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", observations, "ports", List.of()));
        assertThat(hosts.status()).as(hosts.body()).isEqualTo(200);
        int batches = 1;
        if (portScan) {
            Response stored = agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 1,
                    "observations", List.of(), "ports", ports));
            assertThat(stored.status()).as(stored.body()).isEqualTo(200);
            batches = 2;
        }
        Response done = agentPost(r, scan, "complete", Map.of("schemaVersion", 1, "totalBatches", batches,
                "outcome", "COMPLETED", "warnings", warnings));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        return scan;
    }

    private JsonNode risk(Ready r) {
        Response res = r.owner().api().get("/api/v1/homes/" + r.home() + "/risk");
        assertThat(res.status()).as(res.body()).isEqualTo(200);
        return res.json();
    }

    private static JsonNode deduction(JsonNode snapshot, String rule, int port) {
        for (JsonNode d : snapshot.get("breakdown").get("deductions")) {
            if (d.get("ruleId").asString().equals(rule) && d.get("params").path("port").asInt() == port) {
                return d;
            }
        }
        return null;
    }

    private static List<String> statuses(JsonNode list) {
        List<String> out = new java.util.ArrayList<>();
        list.forEach(n -> out.add(n.get("status").asString()));
        return out;
    }

    @Test
    void scansProduceExplainedSnapshotsWithDeltaTriageAndHistory() throws Exception {
        // OpenSSH 7.4p1: SecurityAnalysisTest stores [MOCK] CVEs of 7.2p1 in the shared vulnerability mirror
        tx.executeWithoutResult(s -> vulnerabilities.upsert(new Cve("CVE-2099-1101", Instant.parse(
                "2099-01-01T00:00:00Z"), Instant.parse("2099-01-02T00:00:00Z"), "MOCK vulnerability", "3.1",
                new BigDecimal("8.1"), "CVSS:3.1/MOCK", "HIGH", List.of(), "[]", "Analyzed",
                List.of(new CpeMatch("cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*", "a", "openbsd", "openssh",
                        "7.4", "p1", null, null, null, null, false))), Instant.now()));
        Ready r = ready();
        assertThat(risk(r).get("current").isNull()).isTrue(); // no scan yet

        Map<String, Object> ssh = port(22, "ssh", "OpenSSH", "7.4p1");
        Map<String, Object> telnet = port(23, "telnet", null, null);
        Map<String, Object> telnetAlt = port(2323, "telnet", null, null);
        String first = scan(r, "STANDARD", List.of(ssh, telnet, telnetAlt), List.of());

        JsonNode current = risk(r).get("current");
        assertThat(current.get("scanId").asString()).isEqualTo(first);
        assertThat(current.get("trigger").asString()).isEqualTo("SCAN");
        assertThat(current.get("engineVersion").asString()).isEqualTo(RiskEngine.ENGINE_VERSION);
        // 1/1 host analyzed, STANDARD, every technique, no router integration: 0.40 + 0.2125 + 0.20
        assertThat(current.get("coverage").asDouble()).isEqualTo(0.813);
        assertThat(current.get("provisional").asBoolean()).isFalse();
        assertThat(current.get("coverageDetail").get("hostsAnalyzed").asInt()).isEqualTo(1);
        assertThat(current.get("delta").isNull()).isTrue(); // first snapshot
        JsonNode breakdown = current.get("breakdown");
        double total = breakdown.get("totalDeduction").asDouble();
        assertThat(current.get("score").asInt()).isEqualTo((int) Math.floor(100 - total + 1e-9));
        JsonNode telnetDeduction = deduction(current, "telnet.open", 23);
        assertThat(telnetDeduction).as(breakdown.toString()).isNotNull();
        assertThat(telnetDeduction.get("factors").get("base").asDouble()).isEqualTo(15.0);
        assertThat(telnetDeduction.get("value").asDouble()).isPositive();
        assertThat(breakdown.toString()).contains("CVE-2099-1101");
        assertThat(current.get("topDevices").get(0).get("ip").asString()).isEqualTo(IP);
        int firstScore = current.get("score").asInt();

        // CVEs of the home
        Response cves = r.owner().api().get("/api/v1/homes/" + r.home() + "/vulnerabilities");
        assertThat(cves.status()).as(cves.body()).isEqualTo(200);
        assertThat(cves.body()).contains("CVE-2099-1101");
        assertThat(cves.json().get(0).get("device").get("ip").asString()).isEqualTo(IP);

        // QUICK without telnet: 23 resolved (in the QUICK list), 2323 not covered (still counted)
        String second = scan(r, "QUICK", List.of(ssh), List.of("MDNS_UNAVAILABLE"));
        current = risk(r).get("current");
        assertThat(current.get("scanId").asString()).isEqualTo(second);
        assertThat(current.get("coverage").asDouble()).isEqualTo(0.71); // 0.40 + 0.15 + 0.20 × 0.8
        assertThat(current.get("coverageDetail").get("techniques").get("MDNS").asBoolean()).isFalse();
        assertThat(deduction(current, "telnet.open", 23)).isNull();
        assertThat(deduction(current, "telnet.open", 2323)).isNotNull();
        JsonNode delta = current.get("delta");
        assertThat(delta.get("previousScanId").asString()).isEqualTo(first);
        assertThat(delta.get("scoreChange").asInt()).isEqualTo(current.get("score").asInt() - firstScore).isPositive();
        assertThat(delta.get("removedFindingsCount").asInt()).isEqualTo(1);
        assertThat(delta.get("removedFindings").get(0).get("status").asString()).isEqualTo("RESOLVED");
        assertThat(delta.get("removedFindings").get(0).get("params").get("port").asInt()).isEqualTo(23);
        assertThat(delta.get("newFindingsCount").asInt()).isZero();
        assertThat(delta.get("newDevicesCount").asInt()).isZero();
        int secondScore = current.get("score").asInt();

        // triage: a false positive stops counting, a new TRIAGE snapshot on the same scan
        String alt = deduction(current, "telnet.open", 2323).get("findingId").asString();
        Response marked = r.owner().api().patch("/api/v1/findings/" + alt + "/status",
                Map.of("status", "FALSE_POSITIVE", "reason", "MOCK: porta di test"));
        assertThat(marked.status()).as(marked.body()).isEqualTo(200);
        current = risk(r).get("current");
        assertThat(current.get("trigger").asString()).isEqualTo("TRIAGE");
        assertThat(current.get("scanId").asString()).isEqualTo(second);
        assertThat(current.get("coverage").asDouble()).isEqualTo(0.71);
        assertThat(current.get("score").asInt()).isGreaterThan(secondScore);
        assertThat(current.get("breakdown").get("excluded").get(0).get("findingId").asString()).isEqualTo(alt);
        assertThat(statuses(current.get("delta").get("removedFindings"))).containsExactly("FALSE_POSITIVE");
        // ACKNOWLEDGED → OPEN of a counted finding does not change the score: no snapshot
        String sshCve = current.get("breakdown").get("deductions").get(0).get("findingId").asString();
        assertThat(r.owner().api().patch("/api/v1/findings/" + sshCve + "/status",
                Map.of("status", "ACKNOWLEDGED", "reason", "MOCK: aggiornamento pianificato")).status())
                .isEqualTo(200);
        assertThat(risk(r).get("current").get("id").asString()).isEqualTo(current.get("id").asString());

        // DISCOVERY: no port data, no score; the last computed one stays available
        String discovery = scan(r, "DISCOVERY", List.of(), List.of());
        JsonNode both = risk(r);
        assertThat(both.get("current").get("scanId").asString()).isEqualTo(discovery);
        assertThat(both.get("current").get("score").isNull()).isTrue();
        assertThat(both.get("current").get("notComputedReason").asString()).isEqualTo("PORT_SCAN_REQUIRED");
        assertThat(both.get("lastScored").get("id").asString()).isEqualTo(current.get("id").asString());

        Response history = r.owner().api().get("/api/v1/homes/" + r.home() + "/risk/history");
        assertThat(history.status()).isEqualTo(200);
        List<String> triggers = new java.util.ArrayList<>();
        history.json().forEach(h -> triggers.add(h.get("trigger").asString() + ":" + h.get("scanProfile").asString()));
        assertThat(triggers).containsExactly("SCAN:DISCOVERY", "TRIAGE:QUICK", "SCAN:QUICK", "SCAN:STANDARD");
        assertThat(history.json().get(2).get("scoreChange").asInt()).isEqualTo(secondScore - firstScore);
        assertThat(r.owner().api().get("/api/v1/homes/" + r.home() + "/risk/history?limit=0").status())
                .isEqualTo(400);

        // dashboard overview (M12): last computed score, why the current one is missing, counted findings
        String empty = Fixtures.createHome(r.owner(), "Casa senza scansioni");
        Response overview = r.owner().api().get("/api/v1/overview");
        assertThat(overview.status()).as(overview.body()).isEqualTo(200);
        JsonNode homeRow = null;
        JsonNode emptyRow = null;
        for (JsonNode h : overview.json()) {
            if (h.get("homeId").asString().equals(r.home())) {
                homeRow = h;
            } else if (h.get("homeId").asString().equals(empty)) {
                emptyRow = h;
            }
        }
        assertThat(homeRow).as(overview.body()).isNotNull();
        JsonNode security = homeRow.get("security");
        assertThat(security.get("score").asInt()).isEqualTo(current.get("score").asInt());
        assertThat(security.get("notComputedReason").asString()).isEqualTo("PORT_SCAN_REQUIRED");
        assertThat(security.get("coverage").asDouble()).isEqualTo(0.71);
        assertThat(security.get("devices").asInt()).isEqualTo(1);
        assertThat(security.get("lastScanAt").isNull()).isFalse();
        int counted = 0;
        for (JsonNode n : security.get("openFindings")) {
            counted += n.asInt();
        }
        assertThat(counted).isEqualTo(current.get("breakdown").get("deductionsCount").asInt()
                + current.get("breakdown").get("notScored").asInt());
        assertThat(emptyRow.get("security").get("score").isNull()).isTrue();
        assertThat(emptyRow.get("security").get("devices").asInt()).isZero();

        // another tenant sees nothing
        Account stranger = accounts().individual();
        Response strangerOverview = stranger.api().get("/api/v1/overview");
        assertThat(strangerOverview.status()).isEqualTo(200);
        assertThat(strangerOverview.body()).doesNotContain(r.home());
        assertThat(stranger.api().get("/api/v1/homes/" + r.home() + "/risk").status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/homes/" + r.home() + "/risk/history").status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/homes/" + r.home() + "/vulnerabilities").status()).isEqualTo(404);
    }
}
