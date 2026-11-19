package com.shsc.scans;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Base64;
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
 * Port and service detection (Milestone 9): QUICK/STANDARD profiles, signed port limits,
 * ingestion of the open ports and services, scope check, classification from the services,
 * device detail. [MOCK] data: no real device is scanned.
 */
class PortScanningTest extends IntegrationTest {

    private static final String LAN = "192.168.70.0/24";
    private static final String CAMERA = "00:11:22:00:70:20";

    private record Ready(Account owner, String home, EnrolledAgent agent) {
    }

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    private Ready ready() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa porte");
        String network = Fixtures.createNetwork(owner, home, LAN);
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.9.0", "uptimeSeconds", 5, "interfacesHash", "e".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);
        return new Ready(owner, home, agent);
    }

    private String start(Ready r, String profile) {
        Response created = r.owner().api().post("/api/v1/homes/" + r.home() + "/scans", Map.of("profile", profile));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        assertThat(created.text("profile")).isEqualTo(profile);
        return created.text("id");
    }

    private Response agentPost(Ready r, String scan, String op, Object body) {
        return agents().as(r.agent()).post("/api/v1/agent/scans/" + scan + "/" + op, body);
    }

    private static Map<String, Object> port(String ip, String protocol, int port, Map<String, Object> service) {
        Map<String, Object> p = new HashMap<>(Map.of("ip", ip, "protocol", protocol, "port", port, "state", "OPEN",
                "reason", protocol.equals("TCP") ? "syn-ack" : "udp-response", "observedAt", Instant.now().toString()));
        if (service != null) {
            p.put("service", service);
        }
        return p;
    }

    private static Map<String, Object> service(String name, String status, Map<String, Object> evidence) {
        Map<String, Object> s = new HashMap<>(Map.of("name", name, "status", status,
                "confidence", status.equals("CONFIRMED") ? "HIGH" : "LOW"));
        if (evidence != null) {
            s.put("evidence", evidence);
        }
        return s;
    }

    private static Map<String, Object> obs(String ip, String mac, String method, Map<String, Object> details) {
        Map<String, Object> o = new HashMap<>(Map.of("ip", ip, "method", method, "observedAt", Instant.now().toString()));
        if (mac != null) {
            o.put("mac", mac);
        }
        if (details != null) {
            o.put("details", details);
        }
        return o;
    }

    private static Map<String, Object> batch(int seq, List<Map<String, Object>> observations,
            List<Map<String, Object>> ports) {
        return Map.of("schemaVersion", 1, "batchSeq", seq, "observations", observations, "ports", ports);
    }

    @Test
    void quickScanStoresOpenPortsAndClassifiesFromServices() throws Exception {
        Ready r = ready();
        String scan = start(r, "QUICK");

        // the signed job carries the profile and the port scan limits
        Response next = agents().as(r.agent()).get("/api/v1/agent/jobs/next?wait=0");
        assertThat(next.status()).as(next.body()).isEqualTo(200);
        JsonNode job = json.readTree(Base64.getUrlDecoder().decode(next.text("payload")));
        assertThat(job.get("profile").asString()).isEqualTo("QUICK");
        JsonNode limits = job.get("limits").get("ports");
        assertThat(limits.get("ratePerSecond").asInt()).isEqualTo(300);
        assertThat(limits.get("perHostConcurrency").asInt()).isEqualTo(8);
        assertThat(limits.get("timeoutMillis").asInt()).isEqualTo(1500);

        assertThat(agentPost(r, scan, "ack", null).status()).isEqualTo(200);
        Response progress = agentPost(r, scan, "progress", Map.of("phase", "PORTS", "percent", 50,
                "devicesDiscovered", 1));
        assertThat(progress.status()).as(progress.body()).isEqualTo(200);

        String ip = "192.168.70.20";
        Response hosts = agentPost(r, scan, "results", batch(0, List.of(
                obs(ip, CAMERA, "ARP", null),
                obs(ip, null, "PORTSCAN", Map.of("profile", "QUICK", "listVersion", "2026.11-1",
                        "tcp", Map.of("probed", 40, "open", 3, "closed", 37, "filtered", 0, "openFiltered", 0,
                                "unknown", 0),
                        "udp", Map.of("probed", 6, "open", 1, "closed", 0, "filtered", 0, "openFiltered", 5,
                                "unknown", 0),
                        "paused", false))), List.of()));
        assertThat(hosts.status()).as(hosts.body()).isEqualTo(200);

        Map<String, Object> ports = batch(1, List.of(), List.of(
                port(ip, "TCP", 554, service("rtsp", "CONFIRMED", Map.of("status", 401, "authRequired", true,
                        "server", "MOCK-Camera/2.1"))),
                port(ip, "TCP", 80, service("http", "CONFIRMED", Map.of("status", 200, "server", "App-webs/",
                        "title", "MOCK Network Camera", "loginForm", true))),
                port(ip, "TCP", 22, service("ssh", "PROBABLE", null)),
                port(ip, "UDP", 3702, service("onvif", "CONFIRMED", Map.of("onvifDeviceService", true))),
                port("10.9.9.9", "TCP", 23, null))); // outside the authorized network
        Response stored = agentPost(r, scan, "results", ports);
        assertThat(stored.status()).as(stored.body()).isEqualTo(200);
        assertThat(stored.json().get("accepted").asInt()).isEqualTo(4);
        assertThat(stored.json().get("dropped").asInt()).isEqualTo(1);
        // same batch again: idempotent
        assertThat(agentPost(r, scan, "results", ports).json().get("duplicate").asBoolean()).isTrue();

        Response done = agentPost(r, scan, "complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
        assertThat(done.text("status")).isEqualTo("COMPLETED_WITH_WARNINGS"); // OUT_OF_SCOPE_RESULTS

        JsonNode scanPorts = r.owner().api().get("/api/v1/scans/" + scan + "/ports").json();
        assertThat(scanPorts.size()).isEqualTo(4);
        assertThat(scanPorts.toString()).doesNotContain("10.9.9.9");

        JsonNode devices = r.owner().api().get("/api/v1/homes/" + r.home() + "/devices").json();
        assertThat(devices.size()).isEqualTo(1);
        JsonNode camera = devices.get(0);
        assertThat(camera.get("category").asString()).isEqualTo("IP_CAMERA");
        assertThat(camera.get("detectedCategoryConfidence").asString()).isEqualTo("HIGH");
        assertThat(camera.get("classification").toString()).contains("camera.onvif", "camera.rtsp-service",
                "camera.http-title");
        assertThat(camera.get("services").isNull()).isTrue(); // only in the detail

        JsonNode detail = r.owner().api().get("/api/v1/devices/" + camera.get("id").asString()).json();
        JsonNode services = detail.get("services");
        assertThat(services.get("scanId").asString()).isEqualTo(scan);
        assertThat(services.get("summary").get("tcp").get("closed").asInt()).isEqualTo(37);
        assertThat(services.get("ports").size()).isEqualTo(4);
        JsonNode first = services.get("ports").get(0); // ordered by protocol and port
        assertThat(first.get("protocol").asString() + "/" + first.get("port").asInt()).isEqualTo("TCP/22");
        assertThat(first.get("service").get("status").asString()).isEqualTo("PROBABLE");
        assertThat(services.get("protocols").toString()).contains("\"RTSP\"", "\"ONVIF\"", "\"HTTP\"");
        JsonNode ssh = null;
        for (JsonNode p : services.get("protocols")) {
            if (p.get("protocol").asString().equals("SSH")) {
                ssh = p;
            }
        }
        assertThat(ssh).isNotNull();
        assertThat(ssh.get("confidence").asString()).isEqualTo("LOW"); // port number only
    }

    @Test
    void portResultsAreValidated() throws Exception {
        Ready r = ready();
        String discovery = start(r, "DISCOVERY");
        assertThat(agentPost(r, discovery, "ack", null).status()).isEqualTo(200);
        String ip = "192.168.70.30";

        // a DISCOVERY scan does not scan ports: port results are refused
        Response unexpected = agentPost(r, discovery, "results", batch(0, List.of(),
                List.of(port(ip, "TCP", 80, null))));
        assertThat(unexpected.status()).isEqualTo(400);
        assertThat(unexpected.text("code")).isEqualTo("PORTS_NOT_EXPECTED");
        Response counters = agentPost(r, discovery, "results", batch(0, List.of(obs(ip, null, "PORTSCAN",
                Map.of("profile", "QUICK"))), List.of()));
        assertThat(counters.text("code")).isEqualTo("PORTS_NOT_EXPECTED");
        assertThat(agentPost(r, discovery, "complete", Map.of("schemaVersion", 1, "totalBatches", 0,
                "outcome", "COMPLETED", "warnings", List.of())).status()).isEqualTo(200);

        String standard = start(r, "STANDARD");
        assertThat(agentPost(r, standard, "ack", null).status()).isEqualTo(200);
        Map<String, Object> badState = port(ip, "TCP", 80, null);
        badState.put("state", "VULNERABLE");
        Map<String, Object> badProtocol = port(ip, "SCTP", 80, null);
        Map<String, Object> badPort = port(ip, "TCP", 70000, null);
        Map<String, Object> badName = port(ip, "TCP", 80, service("HTTP <script>", "CONFIRMED", null));
        Map<String, Object> badStatus = port(ip, "TCP", 80, service("http", "VERIFIED", null));
        Map<String, Object> hugeEvidence = port(ip, "TCP", 80, service("http", "CONFIRMED",
                Map.of("title", "x".repeat(4000))));
        for (Map<String, Object> bad : List.of(badState, badProtocol, badPort, badName, badStatus, hugeEvidence)) {
            Response refused = agentPost(r, standard, "results", batch(0, List.of(), List.of(bad)));
            assertThat(refused.status()).as(bad.toString()).isEqualTo(400);
        }
        Response phase = agentPost(r, standard, "progress", Map.of("phase", "EXPLOIT", "percent", 1,
                "devicesDiscovered", 0));
        assertThat(phase.status()).isEqualTo(400);
        assertThat(r.owner().api().get("/api/v1/scans/" + standard + "/ports").json().size()).isZero();
    }
}
