package com.shsc.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * Agent runtime (Milestone 5): heartbeat with self-diagnosis, connectivity state, revocation
 * noticed at the next heartbeat, idempotent event delivery, payload validation, plan limit
 * of agents per home.
 */
class AgentRuntimeTest extends IntegrationTest {

    private static final String HASH_A = "a".repeat(64);
    private static final String HASH_B = "b".repeat(64);

    @Autowired
    JdbcClient jdbc;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    TenantScope tenantScope;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private static Map<String, Object> heartbeat(String hash, List<Map<String, Object>> interfaces, String lastError) {
        Map<String, Object> body = new HashMap<>(Map.of("schemaVersion", 1, "agentVersion", "0.5.0", "uptimeSeconds", 42,
                "interfacesHash", hash, "queueDepth", 3,
                "capabilities", Map.of("privileged", false, "arp", "os_table", "icmp", "unprivileged",
                        "warnings", List.of("ARP_TABLE_ONLY"))));
        body.put("interfaces", interfaces);
        body.put("lastError", lastError);
        return body;
    }

    private static List<Map<String, Object>> lan() {
        return List.of(Map.of("name", "eth0", "mac", "aa:bb:cc:dd:ee:ff", "mtu", 1500,
                "addresses", List.of("192.168.1.20/24", "fd00::20/64")));
    }

    private static Map<String, Object> event(UUID id, String type, Instant at) {
        return Map.of("id", id.toString(), "type", type, "occurredAt", at.toString(), "detail", Map.of("k", 1));
    }

    private Account ownerWithHome() {
        return accounts().individual();
    }

    @Test
    void heartbeatStoresTheSelfDiagnosisAndTheAgentIsOnline() throws Exception {
        Account owner = ownerWithHome();
        String home = Fixtures.createHome(owner, "Casa runtime");
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId()).text("connectivity")).isEqualTo("NEVER_CONNECTED");

        Response hb = agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, lan(), null));
        assertThat(hb.status()).as(hb.body()).isEqualTo(200);
        // below 30 s: a revocation is noticed within 30 s
        assertThat(hb.json().get("heartbeatIntervalSeconds").asInt()).isBetween(10, 29);
        assertThat(hb.text("serverTime")).isNotBlank();

        JsonNode seen = owner.api().get("/api/v1/agents/" + agent.agentId()).json();
        assertThat(seen.get("connectivity").asString()).isEqualTo("ONLINE");
        assertThat(seen.get("capabilities").get("arp").asString()).isEqualTo("os_table");
        assertThat(seen.get("capabilities").get("warnings").get(0).asString()).isEqualTo("ARP_TABLE_ONLY");
        assertThat(seen.get("interfaces").get(0).get("addresses").get(0).asString()).isEqualTo("192.168.1.20/24");
        assertThat(seen.get("queueDepth").asInt()).isEqualTo(3);
        assertThat(seen.get("uptimeSeconds").asLong()).isEqualTo(42);
        assertThat(seen.get("agentVersion").asString()).isEqualTo("0.5.0");

        // interfaces unchanged: only the hash is sent and the stored list is kept
        Response second = agents().as(agent).post("/api/v1/agent/heartbeat",
                heartbeat(HASH_A, null, "GET /api/v1/agent/events: timeout"));
        assertThat(second.status()).isEqualTo(200);
        seen = owner.api().get("/api/v1/homes/" + home + "/agents").json().get(0);
        assertThat(seen.get("interfaces").size()).isEqualTo(1);
        assertThat(seen.get("lastError").asString()).contains("timeout");

        // a new list replaces the previous one
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_B, List.of(), null)).status())
                .isEqualTo(200);
        seen = owner.api().get("/api/v1/agents/" + agent.agentId()).json();
        assertThat(seen.get("interfaces").size()).isZero();
        assertThat(seen.get("lastError").isNull()).isTrue();
    }

    @Test
    void connectivityBecomesStaleThenOfflineWithoutHeartbeats() throws Exception {
        Account owner = ownerWithHome();
        EnrolledAgent agent = agents().enroll(owner, Fixtures.createHome(owner, "Casa offline"));
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, lan(), null)).status())
                .isEqualTo(200);

        lastHeartbeat(owner, agent, "5 minutes");
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId()).text("connectivity")).isEqualTo("STALE");
        lastHeartbeat(owner, agent, "20 minutes");
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId()).text("connectivity")).isEqualTo("OFFLINE");

        // back online with the next heartbeat
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, null, null)).status())
                .isEqualTo(200);
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId()).text("connectivity")).isEqualTo("ONLINE");
    }

    private void lastHeartbeat(Account owner, EnrolledAgent agent, String ago) {
        tenantScope.runAs(owner.tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql(
                "UPDATE agents SET last_heartbeat_at = now() - CAST(:ago AS interval) WHERE id = :id")
                .param("ago", ago).param("id", UUID.fromString(agent.agentId())).update()));
    }

    @Test
    void revokedAgentIsStoppedAtItsNextHeartbeat() throws Exception {
        Account owner = ownerWithHome();
        EnrolledAgent agent = agents().enroll(owner, Fixtures.createHome(owner, "Casa revoca"));
        assertThat(agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, lan(), null)).status())
                .isEqualTo(200);

        assertThat(owner.api().post("/api/v1/agents/" + agent.agentId() + "/revoke", Map.of("reason", "test"))
                .status()).isEqualTo(200);

        Response hb = agents().as(agent).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, null, null));
        assertThat(hb.status()).isEqualTo(401);
        assertThat(hb.text("code")).isEqualTo("AGENT_REVOKED");
        Response events = agents().as(agent).post("/api/v1/agent/events", Map.of("schemaVersion", 1,
                "events", List.of(event(UUID.randomUUID(), "AGENT_STOPPED", Instant.now()))));
        assertThat(events.status()).isEqualTo(401);
        assertThat(events.text("code")).isEqualTo("AGENT_REVOKED");
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId()).text("connectivity")).isEqualTo("REVOKED");
    }

    @Test
    void queuedEventsAreStoredOnceAndVisibleOnlyInTheTenant() throws Exception {
        Account owner = ownerWithHome();
        EnrolledAgent agent = agents().enroll(owner, Fixtures.createHome(owner, "Casa eventi"));
        UUID started = UUID.randomUUID();
        UUID restored = UUID.randomUUID();
        UUID stopped = UUID.randomUUID();
        Instant t0 = Instant.now().minusSeconds(3600);

        Response first = agents().as(agent).post("/api/v1/agent/events", Map.of("schemaVersion", 1, "events", List.of(
                event(started, "AGENT_STARTED", t0), event(restored, "CONNECTION_RESTORED", t0.plusSeconds(60)))));
        assertThat(first.status()).as(first.body()).isEqualTo(200);
        assertThat(first.json().get("accepted").asInt()).isEqualTo(2);

        // re-sent after a lost acknowledgement: duplicates are ignored
        Response again = agents().as(agent).post("/api/v1/agent/events", Map.of("schemaVersion", 1, "events", List.of(
                event(started, "AGENT_STARTED", t0), event(restored, "CONNECTION_RESTORED", t0.plusSeconds(60)),
                event(stopped, "AGENT_STOPPED", Instant.now().plusSeconds(3600)))));
        assertThat(again.json().get("accepted").asInt()).isEqualTo(1);
        assertThat(again.json().get("duplicates").asInt()).isEqualTo(2);

        JsonNode list = owner.api().get("/api/v1/agents/" + agent.agentId() + "/events").json();
        assertThat(list.size()).isEqualTo(3);
        // the future timestamp (wrong agent clock) was replaced by the reception time
        assertThat(list.get(0).get("type").asString()).isEqualTo("AGENT_STOPPED");
        assertThat(Instant.parse(list.get(0).get("occurredAt").asString())).isBefore(Instant.now().plusSeconds(60));
        assertThat(list.get(2).get("id").asString()).isEqualTo(started.toString());
        assertThat(list.get(2).get("detail").get("k").asInt()).isEqualTo(1);

        Account stranger = accounts().individual();
        assertThat(stranger.api().get("/api/v1/agents/" + agent.agentId() + "/events").status()).isEqualTo(404);
    }

    @Test
    void invalidMessagesAreRejected() throws Exception {
        Account owner = ownerWithHome();
        EnrolledAgent agent = agents().enroll(owner, Fixtures.createHome(owner, "Casa validazione"));
        var api = agents().as(agent);

        Map<String, Object> futureSchema = heartbeat(HASH_A, lan(), null);
        futureSchema.put("schemaVersion", 2);
        assertThat(api.post("/api/v1/agent/heartbeat", futureSchema).status()).isEqualTo(400);

        Map<String, Object> badCapability = heartbeat(HASH_A, lan(), null);
        badCapability.put("capabilities", Map.of("privileged", true, "arp", "exploit", "icmp", "raw", "warnings", List.of()));
        assertThat(api.post("/api/v1/agent/heartbeat", badCapability).status()).isEqualTo(400);

        Map<String, Object> badAddress = heartbeat(HASH_A, List.of(Map.of("name", "eth0", "mtu", 1500,
                "addresses", List.of("<script>"))), null);
        assertThat(api.post("/api/v1/agent/heartbeat", badAddress).status()).isEqualTo(400);

        assertThat(api.post("/api/v1/agent/events", Map.of("schemaVersion", 1,
                "events", List.of(event(UUID.randomUUID(), "SCAN_STARTED", Instant.now())))).status()).isEqualTo(400);
        List<Map<String, Object>> tooMany = new ArrayList<>();
        for (int i = 0; i < 101; i++) {
            tooMany.add(event(UUID.randomUUID(), "AGENT_STARTED", Instant.now()));
        }
        assertThat(api.post("/api/v1/agent/events", Map.of("schemaVersion", 1, "events", tooMany)).status())
                .isEqualTo(400);
        Response hugeDetail = api.post("/api/v1/agent/events", Map.of("schemaVersion", 1, "events", List.of(Map.of(
                "id", UUID.randomUUID().toString(), "type", "AGENT_STARTED", "occurredAt", Instant.now().toString(),
                "detail", Map.of("x", "y".repeat(5000))))));
        assertThat(hugeDetail.status()).isEqualTo(400);
        assertThat(hugeDetail.text("code")).isEqualTo("INVALID_EVENT");

        // user credentials are never accepted on the agent API
        assertThat(client().bearer(owner.accessToken()).post("/api/v1/agent/heartbeat", heartbeat(HASH_A, lan(), null))
                .status()).isEqualTo(401);
        assertThat(client().post("/api/v1/agent/heartbeat", heartbeat(HASH_A, lan(), null)).status()).isEqualTo(401);
    }

    @Test
    void activeAgentsPerHomeAreLimitedByThePlan() throws Exception {
        Account owner = ownerWithHome();
        String home = Fixtures.createHome(owner, "Casa limite agent");
        assertThat(owner.api().get("/api/v1/tenants/current").json().get("plan").get("maxAgentsPerHome").asInt())
                .isEqualTo(2);
        // three tokens created while the home has no agent
        String t1 = TestAgents.enrollmentToken(owner, home);
        String t2 = TestAgents.enrollmentToken(owner, home);
        String t3 = TestAgents.enrollmentToken(owner, home);
        Response a1 = agents().tryEnroll(t1, TestAgents.newKeys());
        assertThat(agents().tryEnroll(t2, TestAgents.newKeys()).status()).isEqualTo(201);

        // the limit is enforced again at enrollment, and the token stays usable
        Response third = agents().tryEnroll(t3, TestAgents.newKeys());
        assertThat(third.status()).as(third.body()).isEqualTo(409);
        assertThat(third.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
        assertThat(third.text("resource")).isEqualTo("AGENTS_PER_HOME");
        Response newToken = owner.api().post("/api/v1/homes/" + home + "/agent-enrollment-tokens", null);
        assertThat(newToken.status()).isEqualTo(409);
        assertThat(newToken.text("resource")).isEqualTo("AGENTS_PER_HOME");

        // revoked agents do not count
        assertThat(owner.api().post("/api/v1/agents/" + a1.text("agentId") + "/revoke", null).status()).isEqualTo(200);
        assertThat(agents().tryEnroll(t3, TestAgents.newKeys()).status()).isEqualTo(201);
    }

    @Test
    void onlyTheMostRecentEventsOfAnAgentAreKept() throws Exception {
        Account owner = ownerWithHome();
        EnrolledAgent agent = agents().enroll(owner, Fixtures.createHome(owner, "Casa retention"));
        Instant t0 = Instant.now().minusSeconds(86_400).truncatedTo(ChronoUnit.SECONDS);
        for (int batch = 0; batch < 6; batch++) {
            List<Map<String, Object>> events = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                events.add(event(UUID.randomUUID(), "CAPABILITIES_CHANGED", t0.plusSeconds(batch * 100L + i)));
            }
            Response sent = agents().as(agent).post("/api/v1/agent/events", Map.of("schemaVersion", 1, "events", events));
            assertThat(sent.status()).as(sent.body()).isEqualTo(200);
        }

        // 600 delivered, the 500 most recent kept: the oldest left is the 101st
        List<Instant> kept = tenantScope.callAs(owner.tenantId(), () -> tx.execute(s -> jdbc.sql(
                "SELECT occurred_at FROM agent_events WHERE agent_id = :id ORDER BY occurred_at")
                .param("id", UUID.fromString(agent.agentId()))
                .query((rs, n) -> rs.getObject(1, OffsetDateTime.class).toInstant()).list()));
        assertThat(kept).hasSize(500);
        assertThat(kept.getFirst()).isEqualTo(t0.plusSeconds(100));
        // the dashboard shows the most recent 50
        assertThat(owner.api().get("/api/v1/agents/" + agent.agentId() + "/events").json().size()).isEqualTo(50);
    }
}
