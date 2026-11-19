package com.shsc.alerts;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;
import com.shsc.shared.persistence.TenantScope;

import tools.jackson.databind.JsonNode;

/**
 * Alerts and PDF reports (Milestone 13): deduplication, preferences, e-mails through the (mocked)
 * SMTP sender, resolution, read state, scan failures, agent offline, report generation and
 * download, permissions and tenant isolation. [MOCK] devices: nothing is scanned.
 */
class AlertsReportsTest extends IntegrationTest {

    private static final String LAN = "192.168.73.0/24";
    private static final String IP1 = "192.168.73.20";
    private static final String IP2 = "192.168.73.21";

    @Autowired
    private AlertJobs jobs;

    @Autowired
    private Fixtures fixtures;

    @Autowired
    private TenantScope tenantScope;

    @Autowired
    private TransactionTemplate tx;

    @Autowired
    private JdbcClient jdbc;

    private record Ready(Account owner, String home, EnrolledAgent agent) {
    }

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private Ready ready(String homeName) throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, homeName);
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(heartbeat(agent).status()).isEqualTo(200);
        return new Ready(owner, home, agent);
    }

    private Response heartbeat(EnrolledAgent agent) {
        return agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.13.0", "uptimeSeconds", 5, "interfacesHash", "f".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
    }

    private Response agentPost(Ready r, String scan, String op, Object body) {
        return agents().as(r.agent()).post("/api/v1/agent/scans/" + scan + "/" + op, body);
    }

    private static Map<String, Object> telnet(int port) {
        return Map.of("ip", IP1, "protocol", "TCP", "port", port, "state", "OPEN", "reason", "syn-ack",
                "observedAt", Instant.now().toString(),
                "service", new HashMap<>(Map.of("name", "telnet", "status", "CONFIRMED", "confidence", "HIGH")));
    }

    /** A complete STANDARD scan of the [MOCK] hosts; the open ports belong to IP1. */
    private String scan(Ready r, List<String> ips, List<Map<String, Object>> ports) {
        Response created = r.owner().api().post("/api/v1/homes/" + r.home() + "/scans", Map.of("profile", "STANDARD"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agentPost(r, scan, "ack", null).status()).isEqualTo(200);
        List<Map<String, Object>> observations = new ArrayList<>();
        for (String ip : ips) {
            String mac = "00:11:22:00:73:" + ip.substring(ip.lastIndexOf('.') + 1);
            int open = IP1.equals(ip) ? ports.size() : 0;
            observations.add(Map.of("ip", ip, "mac", mac, "method", "ARP", "observedAt", Instant.now().toString()));
            observations.add(Map.of("ip", ip, "method", "PORTSCAN", "observedAt", Instant.now().toString(),
                    "details", Map.of("profile", "STANDARD", "listVersion", "2026.11-1",
                            "tcp", Map.of("probed", 40, "open", open, "closed", 40 - open, "filtered", 0,
                                    "openFiltered", 0, "unknown", 0),
                            "udp", Map.of("probed", 0, "open", 0, "closed", 0, "filtered", 0, "openFiltered", 0,
                                    "unknown", 0),
                            "paused", false)));
        }
        assertThat(agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", observations, "ports", List.of())).status()).isEqualTo(200);
        Response stored = agentPost(r, scan, "results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "ports", ports));
        assertThat(stored.status()).as(stored.body()).isEqualTo(200);
        Response done = agentPost(r, scan, "complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        return scan;
    }

    private String failedScan(Ready r) {
        Response created = r.owner().api().post("/api/v1/homes/" + r.home() + "/scans", Map.of("profile", "QUICK"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agentPost(r, scan, "ack", null).status()).isEqualTo(200);
        Response done = agentPost(r, scan, "complete", Map.of("schemaVersion", 1, "totalBatches", 0,
                "outcome", "FAILED", "warnings", List.of(), "errorCode", "MOCK_ERROR"));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        return scan;
    }

    private static List<JsonNode> alerts(Account account, String type) {
        Response res = account.api().get("/api/v1/alerts?limit=200");
        assertThat(res.status()).as(res.body()).isEqualTo(200);
        List<JsonNode> out = new ArrayList<>();
        res.json().forEach(a -> {
            if (type == null || type.equals(a.get("type").asString())) {
                out.add(a);
            }
        });
        return out;
    }

    private static int unread(Account account) {
        return account.api().get("/api/v1/alerts/unread-count").json().get("count").asInt();
    }

    /** Sends the pending e-mails and returns the messages the address has received so far. */
    private List<SimpleMailMessage> dispatchAndRead(String email) {
        jobs.dispatchEmails();
        return mailbox().messagesTo(email);
    }

    @Test
    void alertsAreDeduplicatedFilteredByPreferencesResolvedAndEmailed() throws Exception {
        Ready r = ready("Casa alert MOCK");
        String email = r.owner().email();
        int mails = mailbox().messagesTo(email).size(); // account verification

        // 1. a HIGH finding: one alert, on the dashboard and by e-mail (default: e-mail from MEDIUM up)
        scan(r, List.of(IP1), List.of(telnet(23)));
        List<JsonNode> found = alerts(r.owner(), "NEW_FINDING");
        assertThat(found).hasSize(1);
        JsonNode alert = found.get(0);
        assertThat(alert.get("severity").asString()).isEqualTo("HIGH");
        assertThat(alert.get("occurrences").asInt()).isEqualTo(1);
        assertThat(alert.get("homeName").asString()).isEqualTo("Casa alert MOCK");
        assertThat(alert.get("payload").get("ruleId").asString()).isEqualTo("telnet.open");
        assertThat(alert.get("payload").get("params").get("port").asInt()).isEqualTo(23);
        assertThat(alert.get("readAt").isNull()).isTrue();
        assertThat(unread(r.owner())).isEqualTo(1);
        jobs.dispatchEmails();
        SimpleMailMessage mail = mailbox().await(email, mails + 1);
        assertThat(mail.getSubject()).contains("Nuovo problema di sicurezza (Alta): Telnet attivo sulla porta 23");
        assertThat(mail.getText()).contains("Casa alert MOCK", "/alerts", "/alerts/preferences", "Cosa fare:")
                .doesNotContain("#token");

        // 2. the same finding seen again: same alert, one more occurrence, no new e-mail (deduplication)
        scan(r, List.of(IP1), List.of(telnet(23)));
        found = alerts(r.owner(), "NEW_FINDING");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).get("id").asString()).isEqualTo(alert.get("id").asString());
        assertThat(found.get(0).get("occurrences").asInt()).isEqualTo(2);
        assertThat(dispatchAndRead(email)).hasSize(mails + 1);

        // 3. preferences: defaults for every type and channel, then e-mail for new devices, no dashboard for resolutions
        Response prefs = r.owner().api().get("/api/v1/notification-preferences");
        assertThat(prefs.status()).isEqualTo(200);
        assertThat(prefs.json().size()).isEqualTo(AlertType.values().length * AlertType.Channel.values().length);
        Response saved = r.owner().api().put("/api/v1/notification-preferences", Map.of("items", List.of(
                Map.of("type", "NEW_DEVICE", "channel", "EMAIL", "enabled", true, "minSeverity", "LOW"),
                Map.of("type", "FINDING_RESOLVED", "channel", "DASHBOARD", "enabled", false, "minSeverity", "INFO"))));
        assertThat(saved.status()).as(saved.body()).isEqualTo(200);
        assertThat(saved.body()).contains("\"type\":\"NEW_DEVICE\",\"channel\":\"EMAIL\",\"enabled\":true,"
                + "\"minSeverity\":\"LOW\"");
        assertThat(r.owner().api().put("/api/v1/notification-preferences", Map.of("items", List.of(
                Map.of("type", "NOPE", "channel", "EMAIL", "enabled", true, "minSeverity", "LOW")))).status())
                .isEqualTo(400);

        // 4. telnet closed and a new device: the finding alert is resolved, the new device is e-mailed
        scan(r, List.of(IP1, IP2), List.of());
        JsonNode resolved = alerts(r.owner(), "NEW_FINDING").get(0);
        assertThat(resolved.get("resolvedAt").isNull()).isFalse();
        assertThat(alerts(r.owner(), "FINDING_RESOLVED")).isEmpty(); // dashboard disabled by preference
        List<JsonNode> devices = alerts(r.owner(), "NEW_DEVICE");
        assertThat(devices).hasSize(1);
        assertThat(devices.get(0).get("payload").get("devices").get(0).get("ip").asString()).isEqualTo(IP2);
        jobs.dispatchEmails();
        assertThat(mailbox().await(email, mails + 2).getSubject()).contains("Nuovo dispositivo in rete: " + IP2);

        // 5. two telnet ports at once: new alerts (the old one is resolved) and a score drop
        scan(r, List.of(IP1, IP2), List.of(telnet(23), telnet(2323)));
        assertThat(alerts(r.owner(), "NEW_FINDING")).hasSize(3);
        List<JsonNode> drops = alerts(r.owner(), "SCORE_DROPPED");
        assertThat(drops).hasSize(1);
        assertThat(drops.get(0).get("payload").get("scoreChange").asInt())
                .isLessThanOrEqualTo(-AlertService.SCORE_DROP_POINTS);

        // 6. read state: one alert, then all; another tenant sees nothing and cannot touch them
        int before = unread(r.owner());
        assertThat(before).isGreaterThan(1);
        assertThat(r.owner().api().post("/api/v1/alerts/" + alert.get("id").asString() + "/read", null).status())
                .isEqualTo(204);
        assertThat(unread(r.owner())).isEqualTo(before - 1);
        assertThat(alerts(r.owner(), null).stream().filter(a -> a.get("id").asString()
                .equals(alert.get("id").asString())).findFirst().orElseThrow().get("readAt").isNull()).isFalse();
        assertThat(r.owner().api().post("/api/v1/alerts/read-all", null).json().get("count").asInt())
                .isEqualTo(before - 1);
        assertThat(unread(r.owner())).isZero();
        assertThat(r.owner().api().get("/api/v1/alerts?unread=true").json().size()).isZero();
        Account other = accounts().individual();
        assertThat(alerts(other, null)).isEmpty();
        assertThat(other.api().post("/api/v1/alerts/" + alert.get("id").asString() + "/read", null).status())
                .isEqualTo(404);
        assertThat(r.owner().api().get("/api/v1/alerts?limit=0").status()).isEqualTo(400);

        // 7. failed scans of the home are one alert with its occurrences, resolved by the next completed scan
        failedScan(r);
        failedScan(r);
        List<JsonNode> failures = alerts(r.owner(), "SCAN_FAILED");
        assertThat(failures).hasSize(1);
        assertThat(failures.get(0).get("occurrences").asInt()).isEqualTo(2);
        assertThat(failures.get(0).get("payload").get("reason").asString()).isEqualTo("MOCK_ERROR");
        scan(r, List.of(IP1, IP2), List.of(telnet(23), telnet(2323)));
        assertThat(alerts(r.owner(), "SCAN_FAILED").get(0).get("resolvedAt").isNull()).isFalse();

        // 8. agent without heartbeat for 20 minutes: one AGENT_OFFLINE alert, resolved by the next heartbeat
        UUID agentId = UUID.fromString(r.agent().agentId());
        tenantScope.runAs(r.owner().tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql(
                "UPDATE agents SET last_heartbeat_at = :at WHERE id = :id")
                .param("at", OffsetDateTime.now().minusMinutes(20)).param("id", agentId).update()));
        jobs.checkAgents();
        jobs.checkAgents();
        List<JsonNode> offline = alerts(r.owner(), "AGENT_OFFLINE");
        assertThat(offline).hasSize(1);
        assertThat(offline.get(0).get("occurrences").asInt()).isEqualTo(1);
        assertThat(heartbeat(r.agent()).status()).isEqualTo(200);
        assertThat(alerts(r.owner(), "AGENT_OFFLINE").get(0).get("resolvedAt").isNull()).isFalse();
    }

    @Test
    void reportsArePdfsOfACompletedScanForTheUsersWhoMayReadTheFindings() throws Exception {
        Ready r = ready("Casa report MOCK");
        String scan = scan(r, List.of(IP1), List.of(telnet(23)));

        Response requested = r.owner().api().post("/api/v1/scans/" + scan + "/reports", Map.of("locale", "en"));
        assertThat(requested.status()).as(requested.body()).isEqualTo(202);
        assertThat(requested.text("status")).isIn("PENDING", "READY");
        String id = requested.text("id");
        JsonNode report = awaitReady(r.owner(), id);
        assertThat(report.get("pages").asInt()).isPositive();
        assertThat(report.get("sha256").asString()).matches("[0-9a-f]{64}");
        assertThat(r.owner().api().get("/api/v1/homes/" + r.home() + "/reports").body()).contains(id);

        HttpResponse<byte[]> pdf = download(r.owner(), id);
        assertThat(pdf.statusCode()).isEqualTo(200);
        assertThat(pdf.headers().firstValue("content-type").orElse("")).startsWith("application/pdf");
        assertThat(pdf.headers().firstValue("content-disposition").orElse("")).startsWith("attachment;")
                .contains("security-report-").contains("-en.pdf");
        assertThat(pdf.headers().firstValue("cache-control").orElse("")).contains("no-store");
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pdf.body())))
                .isEqualTo(report.get("sha256").asString());
        try (PDDocument doc = Loader.loadPDF(pdf.body())) {
            assertThat(new PDFTextStripper().getText(doc)).contains("Security report", "Home: Casa report MOCK",
                    "Telnet enabled on port 23", "Limits of the analysis");
        }

        // invalid requests
        assertThat(r.owner().api().post("/api/v1/scans/" + scan + "/reports", Map.of("locale", "fr")).status())
                .isEqualTo(400);
        String failed = failedScan(r);
        Response notCompleted = r.owner().api().post("/api/v1/scans/" + failed + "/reports", Map.of("locale", "it"));
        assertThat(notCompleted.status()).isEqualTo(409);
        assertThat(notCompleted.text("code")).isEqualTo("SCAN_NOT_COMPLETED");

        // READ_ONLY reads and downloads, but cannot generate
        Account reader = fixtures.addUser(accounts(), client(), r.owner(), "READ_ONLY", ScopeType.TENANT, null);
        assertThat(reader.api().get("/api/v1/reports/" + id).status()).isEqualTo(200);
        assertThat(download(reader, id).statusCode()).isEqualTo(200);
        assertThat(reader.api().post("/api/v1/scans/" + scan + "/reports", Map.of("locale", "it")).status())
                .isEqualTo(403);

        // another tenant: nothing exists
        Account other = accounts().individual();
        assertThat(other.api().get("/api/v1/reports/" + id).status()).isEqualTo(404);
        assertThat(download(other, id).statusCode()).isEqualTo(404);
        assertThat(other.api().post("/api/v1/scans/" + scan + "/reports", Map.of("locale", "it")).status())
                .isEqualTo(404);
    }

    private JsonNode awaitReady(Account account, String id) throws InterruptedException {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(20));
        while (Instant.now().isBefore(deadline)) {
            Response res = account.api().get("/api/v1/reports/" + id);
            assertThat(res.status()).as(res.body()).isEqualTo(200);
            assertThat(res.text("status")).isNotEqualTo("FAILED");
            if ("READY".equals(res.text("status"))) {
                return res.json();
            }
            Thread.sleep(100);
        }
        throw new AssertionError("report " + id + " not generated");
    }

    private HttpResponse<byte[]> download(Account account, String id) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/reports/" + id
                + "/download")).header("Authorization", "Bearer " + account.accessToken()).GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofByteArray());
    }
}
