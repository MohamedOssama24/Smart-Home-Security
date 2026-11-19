package com.shsc.assistant;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * AI security assistant endpoint (Milestone 16) with the default LOCAL provider: answers grounded
 * in the home data with citations, no data before the first scan, actions refused, validation,
 * permissions, tenant isolation and audit without the question text. [MOCK] devices: nothing is scanned.
 */
class AssistantIntegrationTest extends IntegrationTest {

    private static final String LAN = "192.168.74.0/24";
    private static final String IP1 = "192.168.74.20";

    @Autowired
    private Fixtures fixtures;

    @Autowired
    private TenantScope tenantScope;

    @Autowired
    private TransactionTemplate tx;

    @Autowired
    private JdbcClient jdbc;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private Response ask(Account who, String home, String question, String locale) {
        Map<String, Object> body = new HashMap<>();
        body.put("question", question);
        body.put("locale", locale);
        return who.api().post("/api/v1/homes/" + home + "/assistant/questions", body);
    }

    private static List<String> kinds(Response r) {
        List<String> kinds = new ArrayList<>();
        r.json().path("citations").forEach(c -> kinds.add(c.path("kind").asString()));
        return kinds;
    }

    @Test
    void answersAreGroundedReadOnlyAndAudited() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa assistente");
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);

        // before any scan: nothing is invented
        Response empty = ask(owner, home, "Qual è il mio rischio?", "it");
        assertThat(empty.status()).as(empty.body()).isEqualTo(200);
        assertThat(empty.text("answer")).contains("Non ci sono ancora dati");
        assertThat(empty.json().path("citations").size()).isZero();
        assertThat(empty.text("provider")).isEqualTo("LOCAL");

        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.16.0", "uptimeSeconds", 5, "interfacesHash", "f".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings",
                        List.of()))).status()).isEqualTo(200);
        String scan = scan(owner, home, agent);

        Response risk = ask(owner, home, "What is my risk score?", "en");
        assertThat(risk.status()).isEqualTo(200);
        assertThat(kinds(risk)).containsExactly("SCORE");
        assertThat(risk.text("scanId")).isEqualTo(scan);
        assertThat(risk.json().path("fallback").asBoolean()).isFalse();

        Response fix = ask(owner, home, "What should I fix first?", "en");
        assertThat(fix.text("answer")).contains("Telnet enabled on port 23", "[F1]");
        assertThat(kinds(fix)).contains("FINDING");
        JsonNode finding = fix.json().path("citations").get(0);
        assertThat(finding.path("ip").asString()).isEqualTo(IP1);

        Response device = ask(owner, home, "Com'è messo " + IP1 + "?", "it");
        assertThat(kinds(device)).startsWith("DEVICE").contains("FINDING");

        // actions are refused and nothing is started
        int scans = count(owner, "SELECT count(*) FROM scans");
        Response action = ask(owner, home, "Avvia una scansione", "it");
        assertThat(action.status()).isEqualTo(200);
        assertThat(action.text("answer")).contains("non eseguo azioni");
        assertThat(action.json().path("citations").size()).isZero();
        assertThat(count(owner, "SELECT count(*) FROM scans")).isEqualTo(scans);

        // validation
        assertThat(ask(owner, home, "  ", "it").status()).isEqualTo(400);
        assertThat(ask(owner, home, "x".repeat(501), "it").status()).isEqualTo(400);
        assertThat(ask(owner, home, "ciao\u0007", "it").status()).isEqualTo(400);
        assertThat(ask(owner, home, "ciao", "fr").status()).isEqualTo(400);
        assertThat(ask(owner, home, "riga uno\nriga due", "it").status()).isEqualTo(200);

        // permissions and isolation
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(ask(reader, home, "Quanti dispositivi ho?", "it").status()).isEqualTo(200);
        Account other = accounts().individual();
        assertThat(ask(other, home, "Quanti dispositivi ho?", "it").status()).isEqualTo(404);
        assertThat(ask(owner, UUID.randomUUID().toString(), "ciao", "it").status()).isEqualTo(404);

        // audit: who asked and how it was answered, never the question
        AtomicReference<String> details = new AtomicReference<>();
        tenantScope.runAs(owner.tenantId(), () -> details.set(tx.execute(s -> jdbc.sql(
                "SELECT string_agg(details::text, ' ') FROM audit_logs WHERE action = 'ASSISTANT_QUERY' "
                        + "AND target_id = :home")
                .param("home", UUID.fromString(home)).query(String.class).single())));
        assertThat(details.get()).contains("LOCAL", "questionLength").doesNotContain("scansione", "Quanti");
    }

    private int count(Account owner, String sql) {
        AtomicReference<Integer> n = new AtomicReference<>();
        tenantScope.runAs(owner.tenantId(), () -> n.set(tx.execute(s -> jdbc.sql(sql).query(Integer.class).single())));
        return n.get();
    }

    /** A STANDARD scan of one [MOCK] host with Telnet open on port 23. */
    private String scan(Account owner, String home, EnrolledAgent agent) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "STANDARD"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        String path = "/api/v1/agent/scans/" + scan + "/";
        assertThat(agents().as(agent).post(path + "ack", null).status()).isEqualTo(200);
        String now = Instant.now().toString();
        List<Map<String, Object>> observations = List.of(
                Map.of("ip", IP1, "mac", "00:11:22:00:74:20", "method", "ARP", "observedAt", now),
                Map.of("ip", IP1, "method", "PORTSCAN", "observedAt", now,
                        "details", Map.of("profile", "STANDARD", "listVersion", "2026.11-1",
                                "tcp", Map.of("probed", 40, "open", 1, "closed", 39, "filtered", 0,
                                        "openFiltered", 0, "unknown", 0),
                                "udp", Map.of("probed", 0, "open", 0, "closed", 0, "filtered", 0,
                                        "openFiltered", 0, "unknown", 0),
                                "paused", false)));
        assertThat(agents().as(agent).post(path + "results", Map.of("schemaVersion", 1, "batchSeq", 0,
                "observations", observations, "ports", List.of())).status()).isEqualTo(200);
        Map<String, Object> telnet = Map.of("ip", IP1, "protocol", "TCP", "port", 23, "state", "OPEN",
                "reason", "syn-ack", "observedAt", now,
                "service", new HashMap<>(Map.of("name", "telnet", "status", "CONFIRMED", "confidence", "HIGH")));
        assertThat(agents().as(agent).post(path + "results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "ports", List.of(telnet))).status()).isEqualTo(200);
        Response done = agents().as(agent).post(path + "complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        return scan;
    }
}
