package com.shsc.scans;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

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
 * Manual scan workflow (Milestone 6): creation and its validations, signed jobs delivered by
 * long polling, ack/lease, progress and cancellation, idempotent result batches with scope
 * validation, completion, reaper (agent offline, lease expired, timeout), late upload,
 * revocation, plan limit, roles and tenant isolation, database guarantees.
 */
class ScanWorkflowTest extends IntegrationTest {

    private static final String LAN = "192.168.50.0/24";

    @Autowired
    JdbcClient jdbc;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    TenantScope tenantScope;

    @Autowired
    ScanReaper reaper;

    @Autowired
    Fixtures fixtures;

    /** A home with an authorized network and an online agent. */
    private record Ready(Account owner, String home, String network, EnrolledAgent agent) {
    }

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private Ready ready(Account owner) throws Exception {
        String home = Fixtures.createHome(owner, "Casa scansioni");
        String network = Fixtures.createNetwork(owner, home, LAN);
        authorize(owner, network);
        EnrolledAgent agent = agents().enroll(owner, home);
        heartbeat(agent);
        return new Ready(owner, home, network, agent);
    }

    private static void authorize(Account owner, String network) {
        Response r = owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1"));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
    }

    private void heartbeat(EnrolledAgent agent) {
        Response r = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.6.0", "uptimeSeconds", 5, "interfacesHash", "c".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
    }

    private static Response startScan(Account user, String home) {
        return user.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
    }

    private static String queuedScan(Account user, String home) {
        Response r = startScan(user, home);
        assertThat(r.status()).as(r.body()).isEqualTo(202);
        assertThat(r.text("status")).isEqualTo("QUEUED");
        return r.text("id");
    }

    private Response agentPost(EnrolledAgent agent, String scan, String action, Object body) {
        return agents().as(agent).post("/api/v1/agent/scans/" + scan + "/" + action, body);
    }

    private static Map<String, Object> progress(String phase, int percent) {
        return Map.of("phase", phase, "percent", percent, "devicesDiscovered", 1);
    }

    private static Map<String, Object> observation(String ip, String mac, String method) {
        Map<String, Object> o = new HashMap<>(Map.of("ip", ip, "method", method, "iface", "eth0",
                "observedAt", Instant.now().toString()));
        if (mac != null) {
            o.put("mac", mac);
        }
        return o;
    }

    private static Map<String, Object> batch(int seq, List<Map<String, Object>> observations) {
        return Map.of("schemaVersion", 1, "batchSeq", seq, "observations", observations);
    }

    private static Map<String, Object> complete(int totalBatches, String outcome, List<String> warnings) {
        return Map.of("schemaVersion", 1, "totalBatches", totalBatches, "outcome", outcome, "warnings", warnings);
    }

    private void sql(Account owner, String statement, String scan) {
        tenantScope.runAs(owner.tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql(statement)
                .param("id", UUID.fromString(scan)).update()));
    }

    private static JsonNode scan(Account user, String scan) {
        Response r = user.api().get("/api/v1/scans/" + scan);
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        return r.json();
    }

    // ------------------------------------------------------------------ happy path

    @Test
    void manualScanGoesFromClickToResultsWithASignedJob() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        JsonNode queued = scan(r.owner(), scanId);
        assertThat(queued.get("trigger").asString()).isEqualTo("MANUAL");
        assertThat(queued.get("agentId").asString()).isEqualTo(r.agent().agentId());
        assertThat(queued.get("targets").get(0).get("cidr").asString()).isEqualTo(LAN);
        assertThat(r.owner().api().get("/api/v1/homes/" + r.home() + "/scans").json().get(0).get("id").asString())
                .isEqualTo(scanId);

        // the agent collects the job and verifies the signature with the key received at enrollment
        String jobKey = agents().as(r.agent()).get("/api/v1/agent/session").text("jobSigningKey");
        Response next = agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=0");
        assertThat(next.status()).as(next.body()).isEqualTo(200);
        byte[] payload = Base64.getUrlDecoder().decode(next.text("payload"));
        assertThat(verify(jobKey, payload, next.text("signature"))).isTrue();
        byte[] tampered = new String(payload, StandardCharsets.UTF_8).replace(LAN, "192.168.99.0/24")
                .getBytes(StandardCharsets.UTF_8);
        assertThat(verify(jobKey, tampered, next.text("signature"))).isFalse();
        JsonNode job = json.readTree(payload);
        assertThat(job.get("scanId").asString()).isEqualTo(scanId);
        assertThat(job.get("agentId").asString()).isEqualTo(r.agent().agentId());
        assertThat(job.get("profile").asString()).isEqualTo("DISCOVERY");
        assertThat(job.get("targets").get(0).get("cidr").asString()).isEqualTo(LAN);
        assertThat(job.get("limits").get("maxHosts").asInt()).isEqualTo(1024);
        assertThat(Instant.parse(job.get("expiresAt").asString())).isAfter(Instant.now());

        Response ack = agentPost(r.agent(), scanId, "ack", null);
        assertThat(ack.status()).as(ack.body()).isEqualTo(200);
        assertThat(ack.json().get("leaseSeconds").asLong()).isPositive();
        assertThat(agentPost(r.agent(), scanId, "ack", null).status()).isEqualTo(200); // repeated: idempotent
        assertThat(agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=0").status()).isEqualTo(204);

        Response p = agentPost(r.agent(), scanId, "progress", progress("DISCOVERY", 40));
        assertThat(p.status()).as(p.body()).isEqualTo(200);
        assertThat(p.json().get("cancelRequested").asBoolean()).isFalse();
        JsonNode running = scan(r.owner(), scanId);
        assertThat(running.get("status").asString()).isEqualTo("RUNNING");
        assertThat(running.get("progress").get("phase").asString()).isEqualTo("DISCOVERY");
        assertThat(running.get("progress").get("percent").asInt()).isEqualTo(40);

        // one address outside the authorized network is dropped, not stored
        List<Map<String, Object>> observations = List.of(observation("192.168.50.10", "aa:bb:cc:00:00:10", "ARP"),
                observation("192.168.50.2", "aa:bb:cc:00:00:02", "SELF"), observation("10.9.9.9", null, "ARP"));
        Response b0 = agentPost(r.agent(), scanId, "results", batch(0, observations));
        assertThat(b0.status()).as(b0.body()).isEqualTo(200);
        assertThat(b0.json().get("accepted").asInt()).isEqualTo(2);
        assertThat(b0.json().get("dropped").asInt()).isEqualTo(1);
        Response again = agentPost(r.agent(), scanId, "results", batch(0, observations));
        assertThat(again.json().get("duplicate").asBoolean()).isTrue();

        Response done = agentPost(r.agent(), scanId, "complete", complete(1, "COMPLETED", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        assertThat(done.text("status")).isEqualTo("COMPLETED_WITH_WARNINGS");
        assertThat(agentPost(r.agent(), scanId, "complete", complete(1, "COMPLETED", List.of())).text("status"))
                .isEqualTo("COMPLETED_WITH_WARNINGS"); // repeated: same answer

        JsonNode finished = scan(r.owner(), scanId);
        assertThat(finished.get("devicesDiscovered").asInt()).isEqualTo(2);
        assertThat(finished.get("outOfScopeDropped").asInt()).isEqualTo(1);
        assertThat(finished.get("warnings").get(0).asString()).isEqualTo("OUT_OF_SCOPE_RESULTS");
        assertThat(finished.get("completedAt").isNull()).isFalse();
        List<String> states = new ArrayList<>();
        finished.get("events").forEach(e -> states.add(e.get("toStatus").asString()));
        assertThat(states).containsExactly("PENDING", "QUEUED", "RUNNING", "COMPLETED_WITH_WARNINGS");

        JsonNode devices = r.owner().api().get("/api/v1/scans/" + scanId + "/devices").json();
        assertThat(devices.size()).isEqualTo(2);
        assertThat(devices.toString()).contains("aa:bb:cc:00:00:10").doesNotContain("10.9.9.9");

        String audit = r.owner().api().get("/api/v1/audit-logs?limit=50").body();
        assertThat(audit).contains("SCAN_REQUESTED").contains("SCAN_RESULTS_OUT_OF_SCOPE");
    }

    @Test
    void cleanResultsCompleteWithoutWarnings() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), scanId, "ack", null);
        agentPost(r.agent(), scanId, "results", batch(0, List.of(observation("192.168.50.7", "aa:bb:cc:00:00:07", "ARP"))));
        agentPost(r.agent(), scanId, "results", batch(1, List.of()));
        Response done = agentPost(r.agent(), scanId, "complete", complete(2, "COMPLETED", List.of()));
        assertThat(done.text("status")).isEqualTo("COMPLETED");
        // reduced coverage reported by the agent becomes a visible warning, never a silent success
        String other = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), other, "ack", null);
        assertThat(agentPost(r.agent(), other, "complete", complete(0, "COMPLETED", List.of("ARP_TABLE_ONLY")))
                .text("status")).isEqualTo("COMPLETED_WITH_WARNINGS");
    }

    // ------------------------------------------------------------------ validation at creation

    @Test
    void creationIsValidatedBeforeAnythingIsWritten() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa validazioni");
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(startScan(owner, home).text("code")).isEqualTo("NO_AUTHORIZED_NETWORK");
        authorize(owner, network);
        assertThat(startScan(owner, home).text("code")).isEqualTo("AGENT_OFFLINE");
        EnrolledAgent agent = agents().enroll(owner, home);
        assertThat(startScan(owner, home).text("code")).isEqualTo("AGENT_OFFLINE"); // never connected
        heartbeat(agent);

        Response deep = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DEEP"));
        assertThat(deep.status()).isEqualTo(400); // plan-gated profiles come with the plans (M17)
        assertThat(deep.text("code")).isEqualTo("PROFILE_NOT_AVAILABLE");
        Response badKey = owner.api().send("POST", "/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"),
                Map.of("Idempotency-Key", "no spaces!"));
        assertThat(badKey.status()).isEqualTo(400);
        assertThat(owner.api().get("/api/v1/homes/" + home + "/scans").json().size()).isZero();

        // double click: same Idempotency-Key → same scan
        Map<String, String> key = Map.of("Idempotency-Key", "click-" + UUID.randomUUID());
        Response first = owner.api().send("POST", "/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"), key);
        Response second = owner.api().send("POST", "/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"), key);
        assertThat(first.status()).isEqualTo(202);
        assertThat(second.status()).isEqualTo(200);
        assertThat(second.text("id")).isEqualTo(first.text("id"));

        Response busy = startScan(owner, home);
        assertThat(busy.status()).isEqualTo(409);
        assertThat(busy.text("code")).isEqualTo("SCAN_ALREADY_ACTIVE");
        assertThat(busy.text("scanId")).isEqualTo(first.text("id"));
        assertThat(owner.api().get("/api/v1/homes/" + home + "/scans").json().size()).isEqualTo(1);
    }

    @Test
    void planLimitsManualScansPerHomePerDay() throws Exception {
        Ready r = ready(accounts().individual());
        for (int i = 0; i < 10; i++) {
            String id = queuedScan(r.owner(), r.home());
            assertThat(r.owner().api().post("/api/v1/scans/" + id + "/cancel", null).status()).isEqualTo(202);
        }
        Response limited = startScan(r.owner(), r.home());
        assertThat(limited.status()).isEqualTo(409);
        assertThat(limited.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
        assertThat(limited.text("resource")).isEqualTo("SCANS_PER_DAY");
    }

    // ------------------------------------------------------------------ roles and tenants

    @Test
    void onlyAuthorizedUsersAndTheAssignedAgentCanTouchAScan() throws Exception {
        Account admin = accounts().business("Scansioni Srl");
        Ready r = ready(admin);
        Account readOnly = fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.TENANT, null);
        Account stranger = accounts().individual();
        String scanId = queuedScan(admin, r.home());

        assertThat(readOnly.api().get("/api/v1/scans/" + scanId).status()).isEqualTo(200);
        assertThat(readOnly.api().get("/api/v1/scans/" + scanId + "/devices").status()).isEqualTo(200);
        assertThat(readOnly.api().post("/api/v1/scans/" + scanId + "/cancel", null).status()).isEqualTo(403);
        assertThat(startScan(readOnly, r.home()).status()).isEqualTo(403);

        assertThat(stranger.api().get("/api/v1/scans/" + scanId).status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/scans/" + scanId + "/devices").status()).isEqualTo(404);
        assertThat(stranger.api().post("/api/v1/scans/" + scanId + "/cancel", null).status()).isEqualTo(404);
        assertThat(stranger.api().get("/api/v1/homes/" + r.home() + "/scans").status()).isEqualTo(404);
        assertThat(startScan(stranger, r.home()).status()).isEqualTo(404);

        // another agent of the same tenant (other home) does not see the job nor the scan
        String otherHome = Fixtures.createHome(admin, "Altra casa");
        EnrolledAgent other = agents().enroll(admin, otherHome);
        assertThat(agents().as(other).get("/api/v1/agent/jobs/next?wait=0").status()).isEqualTo(204);
        assertThat(agentPost(other, scanId, "ack", null).status()).isEqualTo(404);
        assertThat(agentPost(other, scanId, "results", batch(0, List.of())).status()).isEqualTo(404);
        // a user token is not accepted on the agent API
        assertThat(admin.api().get("/api/v1/agent/jobs/next?wait=0").status()).isEqualTo(401);
        assertThat(scan(admin, scanId).get("status").asString()).isEqualTo("QUEUED");
    }

    // ------------------------------------------------------------------ cancel

    @Test
    void cancelIsImmediateWhenQueuedAndConfirmedByTheAgentWhenRunning() throws Exception {
        Ready r = ready(accounts().individual());
        String queued = queuedScan(r.owner(), r.home());
        Response cancelled = r.owner().api().post("/api/v1/scans/" + queued + "/cancel", null);
        assertThat(cancelled.status()).isEqualTo(202);
        assertThat(cancelled.text("status")).isEqualTo("CANCELLED");
        assertThat(agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=0").status()).isEqualTo(204);
        assertThat(agentPost(r.agent(), queued, "ack", null).text("code")).isEqualTo("SCAN_NOT_RUNNING");
        assertThat(r.owner().api().post("/api/v1/scans/" + queued + "/cancel", null).text("code"))
                .isEqualTo("SCAN_ALREADY_FINISHED");

        String running = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), running, "ack", null);
        Response requested = r.owner().api().post("/api/v1/scans/" + running + "/cancel", null);
        assertThat(requested.status()).isEqualTo(202);
        assertThat(requested.text("status")).isEqualTo("RUNNING");
        assertThat(requested.text("cancelRequestedAt")).isNotBlank();
        assertThat(agentPost(r.agent(), running, "progress", progress("DISCOVERY", 10)).json()
                .get("cancelRequested").asBoolean()).isTrue();
        // partial results are kept
        agentPost(r.agent(), running, "results", batch(0, List.of(observation("192.168.50.9", null, "ARP"))));
        Response done = agentPost(r.agent(), running, "complete", complete(1, "CANCELLED", List.of()));
        assertThat(done.text("status")).isEqualTo("CANCELLED");
        JsonNode s = scan(r.owner(), running);
        assertThat(s.get("devicesDiscovered").asInt()).isEqualTo(1);
        assertThat(s.get("events").get(3).get("reason").asString()).isEqualTo("USER_CANCELLED");
    }

    @Test
    void anAgentStoppingOnItsOwnFailsTheScanAndMissingBatchesAreRefused() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), scanId, "ack", null);
        agentPost(r.agent(), scanId, "results", batch(1, List.of()));
        Response missing = agentPost(r.agent(), scanId, "complete", complete(2, "COMPLETED", List.of()));
        assertThat(missing.status()).isEqualTo(409);
        assertThat(missing.text("code")).isEqualTo("MISSING_BATCHES");
        assertThat(missing.json().get("missing").get(0).asInt()).isZero();
        Response aborted = agentPost(r.agent(), scanId, "complete", complete(1, "CANCELLED", List.of()));
        assertThat(aborted.status()).isEqualTo(409); // batch 0 still missing
        agentPost(r.agent(), scanId, "results", batch(0, List.of()));
        assertThat(agentPost(r.agent(), scanId, "complete", complete(2, "CANCELLED", List.of())).text("status"))
                .isEqualTo("FAILED");
        assertThat(scan(r.owner(), scanId).get("failureReason").asString()).isEqualTo("AGENT_ABORTED");
    }

    // ------------------------------------------------------------------ reaper, late upload, revocation

    @Test
    void aJobNotCollectedInTimeFailsBecauseTheAgentIsOffline() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        sql(r.owner(), "UPDATE scans SET job_expires_at = now() - interval '1 second' WHERE id = :id", scanId);
        assertThat(agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=0").status()).isEqualTo(204);
        reaper.reap();
        JsonNode s = scan(r.owner(), scanId);
        assertThat(s.get("status").asString()).isEqualTo("FAILED");
        assertThat(s.get("failureReason").asString()).isEqualTo("AGENT_OFFLINE");
        assertThat(agentPost(r.agent(), scanId, "ack", null).status()).isEqualTo(409);
        // the home is free again
        assertThat(startScan(r.owner(), r.home()).status()).isEqualTo(202);
    }

    @Test
    void anExpiredLeaseFailsTheScanAndLateResultsAreAcceptedWithin24Hours() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), scanId, "ack", null);
        sql(r.owner(), "UPDATE scans SET lease_expires_at = now() - interval '1 second' WHERE id = :id", scanId);
        reaper.reap();
        assertThat(scan(r.owner(), scanId).get("failureReason").asString()).isEqualTo("AGENT_LOST");
        Response p = agentPost(r.agent(), scanId, "progress", progress("DISCOVERY", 50));
        assertThat(p.status()).isEqualTo(409);
        assertThat(p.text("code")).isEqualTo("SCAN_NOT_RUNNING");

        // the agent was offline: it uploads what it had queued when it is back
        Response late = agentPost(r.agent(), scanId, "results",
                batch(0, List.of(observation("192.168.50.20", "aa:bb:cc:00:00:20", "ARP"))));
        assertThat(late.status()).as(late.body()).isEqualTo(200);
        Response done = agentPost(r.agent(), scanId, "complete", complete(1, "COMPLETED", List.of()));
        assertThat(done.text("status")).isEqualTo("COMPLETED_WITH_WARNINGS");
        JsonNode s = scan(r.owner(), scanId);
        assertThat(s.get("warnings").toString()).contains("LATE_UPLOAD");
        assertThat(s.get("failureReason").isNull()).isTrue();
        assertThat(s.get("devicesDiscovered").asInt()).isEqualTo(1);

        // beyond 24 hours late results are refused
        String old = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), old, "ack", null);
        sql(r.owner(), "UPDATE scans SET lease_expires_at = now() - interval '1 second' WHERE id = :id", old);
        reaper.reap();
        sql(r.owner(), "UPDATE scans SET completed_at = now() - interval '25 hours' WHERE id = :id", old);
        Response tooLate = agentPost(r.agent(), old, "results", batch(0, List.of()));
        assertThat(tooLate.status()).isEqualTo(409);
        assertThat(tooLate.text("code")).isEqualTo("SCAN_NOT_ACCEPTING_RESULTS");
    }

    @Test
    void maximumDurationAndAgentRevocationFailRunningScans() throws Exception {
        Ready r = ready(accounts().individual());
        String slow = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), slow, "ack", null);
        sql(r.owner(), "UPDATE scans SET deadline_at = now() - interval '1 second' WHERE id = :id", slow);
        reaper.reap();
        assertThat(scan(r.owner(), slow).get("failureReason").asString()).isEqualTo("TIMEOUT");

        String running = queuedScan(r.owner(), r.home());
        agentPost(r.agent(), running, "ack", null);
        assertThat(r.owner().api().post("/api/v1/agents/" + r.agent().agentId() + "/revoke", Map.of("reason", "test"))
                .status()).isEqualTo(200);
        JsonNode s = scan(r.owner(), running);
        assertThat(s.get("status").asString()).isEqualTo("FAILED");
        assertThat(s.get("failureReason").asString()).isEqualTo("AGENT_REVOKED");
        assertThat(agentPost(r.agent(), running, "progress", progress("DISCOVERY", 1)).status()).isEqualTo(401);
    }

    // ------------------------------------------------------------------ long polling

    @Test
    void aWaitingAgentReceivesTheJobAsSoonAsTheScanIsQueued() throws Exception {
        Ready r = ready(accounts().individual());
        long started = System.nanoTime();
        CompletableFuture<Response> waiting = CompletableFuture.supplyAsync(
                () -> agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=20"));
        Thread.sleep(1000);
        String scanId = queuedScan(r.owner(), r.home());
        Response job = waiting.get(15, TimeUnit.SECONDS);
        assertThat(job.status()).as(job.body()).isEqualTo(200);
        assertThat(json.readTree(Base64.getUrlDecoder().decode(job.text("payload"))).get("scanId").asString())
                .isEqualTo(scanId);
        assertThat(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started)).isLessThan(10);
    }

    // ------------------------------------------------------------------ database guarantees

    @Test
    void theDatabaseAcceptsOnlyManualScansAndOneActiveScanPerHome() throws Exception {
        Ready r = ready(accounts().individual());
        String scanId = queuedScan(r.owner(), r.home());
        assertThatThrownBy(() -> sql(r.owner(), "UPDATE scans SET trigger = 'SCHEDULED' WHERE id = :id", scanId))
                .hasMessageContaining("scans_trigger_check");
        assertThatThrownBy(() -> sql(r.owner(), """
                INSERT INTO scans (tenant_id, home_id, agent_id, profile, status, requested_by, requested_at)
                SELECT tenant_id, home_id, agent_id, profile, 'QUEUED', requested_by, now() FROM scans WHERE id = :id""",
                scanId)).hasMessageContaining("scans_one_active_per_home");
    }

    private static boolean verify(String rawPublicKey, byte[] payload, String signature) throws Exception {
        byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
        byte[] raw = Base64.getUrlDecoder().decode(rawPublicKey);
        byte[] der = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, der, 0, prefix.length);
        System.arraycopy(raw, 0, der, prefix.length, raw.length);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)));
        verifier.update(payload);
        return verifier.verify(Base64.getUrlDecoder().decode(signature));
    }
}
