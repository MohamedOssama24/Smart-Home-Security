package com.shsc.findings;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
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
import com.shsc.vulnintel.VulnerabilityRepository.KevEntry;

import tools.jackson.databind.JsonNode;

/**
 * Security analysis at scan completion (Milestone 10): CVE matching of the declared products,
 * configuration rules, deduplication, resolution only of what a scan covered, re-detection,
 * triage and tenant isolation. [MOCK] CVEs (CVE-2099-*) and devices: nothing is scanned.
 */
class SecurityAnalysisTest extends IntegrationTest {

    private static final String LAN = "192.168.71.0/24";
    private static final String IP = "192.168.71.20";
    private static final String MAC = "00:11:22:00:71:20";

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
        String home = Fixtures.createHome(owner, "Casa analisi");
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.10.0", "uptimeSeconds", 5, "interfacesHash", "e".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);
        return new Ready(owner, home, agent);
    }

    private static CpeMatch cpe(String vendor, String product, String version, String update, String endExcl,
            boolean platform) {
        return new CpeMatch("cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":" + update + ":*:*:*:*:*:*",
                "a", vendor, product, version, update, null, null, null, endExcl, platform);
    }

    private static Cve cve(String id, String severity, String score, CpeMatch match) {
        return new Cve(id, Instant.parse("2099-01-01T00:00:00Z"), Instant.parse("2099-01-02T00:00:00Z"),
                "MOCK vulnerability " + id, "3.1", new BigDecimal(score), "CVSS:3.1/MOCK", severity, List.of(),
                "[]", "Analyzed", List.of(match));
    }

    /** Only the [MOCK] CVEs of this test in the (global) mirror. */
    private void mockFeeds() {
        Instant now = Instant.now();
        tx.executeWithoutResult(s -> {
            vulnerabilities.retainOnly(List.of());
            vulnerabilities.upsert(cve("CVE-2099-1001", "HIGH", "7.5", cpe("openbsd", "openssh", "7.2", "p1", null,
                    false)), now);
            vulnerabilities.upsert(cve("CVE-2099-1002", "CRITICAL", "9.8", cpe("openbsd", "openssh", "7.2", "*",
                    null, true)), now);
            vulnerabilities.upsert(cve("CVE-2099-1003", "MEDIUM", "5.3", cpe("f5", "nginx", "*", "*", "1.20.1",
                    false)), now);
            vulnerabilities.upsert(cve("CVE-2099-1004", "CRITICAL", "9.8", cpe("apache", "http_server", "*", "*",
                    null, false)), now);
            vulnerabilities.replaceKev(List.of(new KevEntry("CVE-2099-1001", "MOCK", "MOCK", "MOCK KEV",
                    LocalDate.parse("2099-01-03"), null, false)), now);
        });
    }

    private Response agentPost(Ready r, String scan, String op, Object body) {
        return agents().as(r.agent()).post("/api/v1/agent/scans/" + scan + "/" + op, body);
    }

    private static Map<String, Object> port(String protocol, int port, String name, String product, String version,
            Map<String, Object> evidence) {
        Map<String, Object> service = new HashMap<>(Map.of("name", name, "status", "CONFIRMED", "confidence", "HIGH"));
        if (product != null) {
            service.put("product", product);
        }
        if (version != null) {
            service.put("version", version);
        }
        if (evidence != null) {
            service.put("evidence", evidence);
        }
        return Map.of("ip", IP, "protocol", protocol, "port", port, "state", "OPEN", "reason", "syn-ack",
                "observedAt", Instant.now().toString(), "service", service);
    }

    /** One complete scan of the [MOCK] device with these open ports. */
    private String scan(Ready r, String profile, List<Map<String, Object>> ports) {
        Response created = r.owner().api().post("/api/v1/homes/" + r.home() + "/scans", Map.of("profile", profile));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agentPost(r, scan, "ack", null).status()).isEqualTo(200);
        Map<String, Object> summary = Map.of("profile", profile, "listVersion", "2026.11-1",
                "tcp", Map.of("probed", 40, "open", ports.size(), "closed", 40 - ports.size(), "filtered", 0,
                        "openFiltered", 0, "unknown", 0),
                "udp", Map.of("probed", 0, "open", 0, "closed", 0, "filtered", 0, "openFiltered", 0, "unknown", 0),
                "paused", false);
        List<Map<String, Object>> observations = List.of(
                Map.of("ip", IP, "mac", MAC, "method", "ARP", "observedAt", Instant.now().toString()),
                Map.of("ip", IP, "method", "PORTSCAN", "observedAt", Instant.now().toString(), "details", summary));
        Response hosts = agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", observations, "ports", List.of()));
        assertThat(hosts.status()).as(hosts.body()).isEqualTo(200);
        Response stored = agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "ports", ports));
        assertThat(stored.status()).as(stored.body()).isEqualTo(200);
        Response done = agentPost(r, scan, "complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        return scan;
    }

    private static JsonNode find(JsonNode list, String rule, Integer port, String cve) {
        for (JsonNode f : list) {
            if (f.get("ruleId").asString().equals(rule)
                    && (port == null || !f.get("port").isNull() && f.get("port").asInt() == port)
                    && (cve == null || cve.equals(f.get("cveId").asString()))) {
                return f;
            }
        }
        return null;
    }

    private JsonNode findings(Ready r) {
        Response list = r.owner().api().get("/api/v1/homes/" + r.home() + "/findings");
        assertThat(list.status()).as(list.body()).isEqualTo(200);
        return list.json();
    }

    @Test
    void scanCompletionAnalyzesResolvesAndReopensFindings() throws Exception {
        mockFeeds();
        Ready r = ready();
        Map<String, Object> ssh = port("TCP", 22, "ssh", "OpenSSH", "7.2p1", Map.of("banner", "SSH-2.0-MOCK"));
        Map<String, Object> web = port("TCP", 80, "http", "nginx", "1.18.0", Map.of("status", 200,
                "loginForm", true, "title", "MOCK login"));
        Map<String, Object> telnet = port("TCP", 23, "telnet", null, null, null);
        Map<String, Object> telnetAlt = port("TCP", 2323, "telnet", null, null, null);
        Map<String, Object> coyote = port("TCP", 8080, "http", "Apache-Coyote", "1.1", Map.of("status", 404));
        String first = scan(r, "STANDARD", List.of(ssh, web, telnet, telnetAlt, coyote));

        JsonNode list = findings(r);
        JsonNode kevCve = find(list, "cve.version-match", 22, "CVE-2099-1001");
        assertThat(kevCve).as(list.toString()).isNotNull();
        assertThat(kevCve.get("type").asString()).isEqualTo("CONFIRMED_VULNERABILITY"); // banner version, exact
        assertThat(kevCve.get("severity").asString()).isEqualTo("CRITICAL"); // HIGH raised: known exploited
        assertThat(kevCve.get("titleKey").asString()).isEqualTo("findings.rule.cve-version-match.title");
        assertThat(kevCve.get("device").get("ip").asString()).isEqualTo(IP);
        JsonNode platform = find(list, "cve.version-match", 22, "CVE-2099-1002");
        assertThat(platform.get("type").asString()).isEqualTo("POTENTIAL_RISK"); // needs another component
        assertThat(platform.get("confidence").asString()).isEqualTo("LOW");
        JsonNode range = find(list, "cve.version-match", 80, "CVE-2099-1003");
        assertThat(range.get("type").asString()).isEqualTo("POTENTIAL_RISK"); // HTTP Server header
        assertThat(find(list, "http.login-cleartext", 80, null)).isNotNull();
        assertThat(find(list, "telnet.open", 23, null)).isNotNull();
        assertThat(find(list, "telnet.open", 2323, null)).isNotNull();
        // Apache-Coyote is not Apache httpd: no CVE on 8080, the vendor alone never matches
        assertThat(list.toString()).doesNotContain("CVE-2099-1004");
        for (JsonNode f : list) {
            assertThat(f.get("ruleId").asString().startsWith("cve.") && f.get("port").asInt() == 8080).isFalse();
        }
        assertThat(list.size()).isEqualTo(new java.util.HashSet<>(ids(list)).size()); // deduplicated

        JsonNode detail = r.owner().api().get("/api/v1/findings/" + kevCve.get("id").asString()).json();
        JsonNode cve = detail.get("vulnerabilities").get(0);
        assertThat(cve.get("cveId").asString()).isEqualTo("CVE-2099-1001");
        assertThat(cve.get("matchQuality").asString()).isEqualTo("EXACT_VERSION");
        assertThat(cve.get("kev").asBoolean()).isTrue();
        assertThat(detail.get("evidence").get(0).get("scanId").asString()).isEqualTo(first);

        // filters
        Response critical = r.owner().api().get("/api/v1/homes/" + r.home() + "/findings?severity=CRITICAL");
        assertThat(critical.json().toString()).contains("CVE-2099-1001");
        assertThat(r.owner().api().get("/api/v1/homes/" + r.home() + "/findings?status=BOGUS").status())
                .isEqualTo(400);

        // triage: a reason is required, the change is kept when the finding is detected again
        String platformPath = "/api/v1/findings/" + platform.get("id").asString() + "/status";
        Response noReason = r.owner().api().patch(platformPath, Map.of("status", "FALSE_POSITIVE"));
        assertThat(noReason.status()).isEqualTo(400);
        assertThat(noReason.text("code")).isEqualTo("REASON_REQUIRED");
        Response marked = r.owner().api().patch(platformPath, Map.of("status", "FALSE_POSITIVE",
                "reason", "MOCK: il dispositivo non usa quel sistema"));
        assertThat(marked.status()).as(marked.body()).isEqualTo(200);
        assertThat(marked.json().get("finding").get("status").asString()).isEqualTo("FALSE_POSITIVE");
        assertThat(r.owner().api().patch(platformPath, Map.of("status", "RESOLVED", "reason", "x")).status())
                .isEqualTo(400);

        // QUICK scan without telnet: 23 is in the QUICK list (resolved), 2323 is not (stays open)
        scan(r, "QUICK", List.of(ssh, web, coyote));
        list = findings(r);
        JsonNode resolved = find(list, "telnet.open", 23, null);
        assertThat(resolved.get("status").asString()).isEqualTo("RESOLVED");
        assertThat(resolved.get("resolvedAt").isNull()).isFalse();
        assertThat(find(list, "telnet.open", 2323, null).get("status").asString()).isEqualTo("OPEN");
        assertThat(find(list, "cve.version-match", 22, "CVE-2099-1002").get("status").asString())
                .isEqualTo("FALSE_POSITIVE");
        assertThat(find(list, "cve.version-match", 22, "CVE-2099-1001").get("status").asString())
                .isEqualTo("OPEN");
        Response conflict = r.owner().api().patch("/api/v1/findings/" + resolved.get("id").asString() + "/status",
                Map.of("status", "ACKNOWLEDGED", "reason", "MOCK"));
        assertThat(conflict.status()).isEqualTo(409);

        // telnet back: the same finding reopens
        scan(r, "QUICK", List.of(ssh, web, telnet, coyote));
        JsonNode reopened = find(findings(r), "telnet.open", 23, null);
        assertThat(reopened.get("id").asString()).isEqualTo(resolved.get("id").asString());
        assertThat(reopened.get("status").asString()).isEqualTo("OPEN");

        // another tenant sees nothing
        Account stranger = accounts().individual();
        assertThat(stranger.api().get("/api/v1/findings/" + kevCve.get("id").asString()).status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/homes/" + r.home() + "/findings").status()).isEqualTo(404);
        assertThat(stranger.api().patch(platformPath, Map.of("status", "OPEN")).status()).isEqualTo(404);
    }

    private static List<String> ids(JsonNode list) {
        List<String> out = new ArrayList<>();
        list.forEach(f -> out.add(f.get("ruleId").asString() + "|" + f.get("port") + "|" + f.get("cveId")));
        return out;
    }
}
