package com.shsc.devices;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient.BinaryResponse;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

import tools.jackson.databind.JsonNode;

/**
 * Device images (Milestone 23): the icon declared by the device (UPnP, sent by the agent) becomes
 * the device image; the user's photo is shown first and never replaced by a scan; only real PNG
 * or JPEG are accepted; icons from outside the authorized networks are dropped. [MOCK] images.
 */
class DeviceImageTest extends IntegrationTest {

    private static final String TV_MAC = "00:11:22:00:63:10";

    @Autowired
    private Fixtures fixtures;

    private TestAgents agents() {
        return new TestAgents(this::client, json);
    }

    @Test
    void deviceIconFromTheScanAndUserPhotoFirst() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa immagini");
        String network = Fixtures.createNetwork(owner, home, "192.168.63.0/24");
        Response auth = owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1"));
        assertThat(auth.status()).as(auth.body()).isEqualTo(200);
        EnrolledAgent agent = agents().enroll(owner, home);
        Response heartbeat = agents().as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.9.0", "uptimeSeconds", 5, "interfacesHash", "e".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())));
        assertThat(heartbeat.status()).as(heartbeat.body()).isEqualTo(200);

        byte[] icon = png(120, 120);
        String base = startScan(owner, home, agent);
        // a fake icon (HTML declared as PNG) is refused, the icon of an address outside the networks dropped
        Response fake = agents().as(agent).post(base + "/results", Map.of("schemaVersion", 1, "batchSeq", 1,
                "observations", List.of(), "icons", List.of(icon("192.168.63.10",
                        "<html>MOCK</html>".getBytes()))));
        assertThat(fake.status()).as(fake.body()).isEqualTo(400);
        assertThat(fake.body()).contains("INVALID_ICON");
        uploadScan(agent, base, icon, true);

        String tv = owner.api().get("/api/v1/homes/" + home + "/devices").json().get(0).get("id").asString();
        JsonNode shown = owner.api().get("/api/v1/homes/" + home + "/device-images").json();
        assertThat(shown).hasSize(1);
        assertThat(shown.get(0).get("deviceId").asString()).isEqualTo(tv);
        assertThat(shown.get(0).get("source").asString()).isEqualTo("DEVICE");
        assertThat(shown.get(0).get("origin").asString()).isEqualTo("UPNP");
        assertThat(shown.get(0).get("width").asInt()).isEqualTo(120);
        BinaryResponse image = owner.api().sendBytes("GET", "/api/v1/devices/" + tv + "/image", null, null);
        assertThat(image.status()).isEqualTo(200);
        assertThat(image.body()).isEqualTo(icon);
        assertThat(image.header("Content-Type")).hasValue("image/png");
        assertThat(image.header("X-Content-Type-Options")).hasValue("nosniff");

        // permissions: a read-only user sees the image but cannot upload; other organizations see nothing
        Account reader = fixtures.addUser(accounts(), client(), owner, "READ_ONLY", ScopeType.TENANT, null);
        String path = "/api/v1/devices/" + tv + "/image";
        byte[] photo = jpeg(640, 480);
        assertThat(reader.api().sendBytes("GET", path, null, null).status()).isEqualTo(200);
        assertThat(reader.api().sendBytes("PUT", path, photo, "image/jpeg").status()).isEqualTo(403);
        assertThat(accounts().individual().api().sendBytes("GET", path, null, null).status()).isEqualTo(404);

        // only real PNG/JPEG: an SVG with a script declared as PNG is refused
        BinaryResponse svg = owner.api().sendBytes("PUT", path,
                "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".getBytes(), "image/png");
        assertThat(svg.status()).isEqualTo(400);
        assertThat(new String(svg.body())).contains("INVALID_IMAGE");

        BinaryResponse uploaded = owner.api().sendBytes("PUT", path, photo, "image/jpeg");
        assertThat(uploaded.status()).as(new String(uploaded.body())).isEqualTo(200);
        JsonNode metas = json.readTree(uploaded.body());
        assertThat(metas.get(0).get("source").asString()).isEqualTo("USER");
        assertThat(metas.get(0).get("shown").asBoolean()).isTrue();
        assertThat(metas.get(1).get("source").asString()).isEqualTo("DEVICE");

        // a new scan updates the device icon but never replaces the user's photo
        uploadScan(agent, startScan(owner, home, agent), png(48, 48), false);
        BinaryResponse after = owner.api().sendBytes("GET", path, null, null);
        assertThat(after.body()).isEqualTo(photo);
        assertThat(after.header("Content-Type")).hasValue("image/jpeg");
        BinaryResponse device = owner.api().sendBytes("GET", path + "?source=DEVICE", null, null);
        assertThat(ImageIO.read(new java.io.ByteArrayInputStream(device.body())).getWidth()).isEqualTo(48);

        // removing the photo shows the device icon again
        BinaryResponse removed = owner.api().sendBytes("DELETE", path, null, null);
        assertThat(removed.status()).isEqualTo(200);
        assertThat(owner.api().get("/api/v1/homes/" + home + "/device-images").json().get(0).get("source")
                .asString()).isEqualTo("DEVICE");
    }

    private String startScan(Account owner, String home, EnrolledAgent agent) {
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "DISCOVERY"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String base = "/api/v1/agent/scans/" + created.text("id");
        assertThat(agents().as(agent).post(base + "/ack", null).status()).isEqualTo(200);
        return base;
    }

    private void uploadScan(EnrolledAgent agent, String base, byte[] icon, boolean withOutOfScope) {
        String now = Instant.now().toString();
        Map<String, Object> arp = new HashMap<>(Map.of("ip", "192.168.63.10", "mac", TV_MAC, "method", "ARP",
                "iface", "eth0", "observedAt", now));
        Map<String, Object> ssdp = new HashMap<>(Map.of("ip", "192.168.63.10", "method", "SSDP", "iface", "eth0",
                "observedAt", now, "details", Map.of("manufacturer", "MOCK Vision Inc.", "modelName", "MockTV")));
        Response results = agents().as(agent).post(base + "/results",
                Map.of("schemaVersion", 1, "batchSeq", 0, "observations", List.of(arp, ssdp)));
        assertThat(results.status()).as(results.body()).isEqualTo(200);
        List<Map<String, Object>> icons = withOutOfScope
                ? List.of(icon("192.168.63.10", icon), icon("10.9.9.9", icon))
                : List.of(icon("192.168.63.10", icon));
        Response iconBatch = agents().as(agent).post(base + "/results",
                Map.of("schemaVersion", 1, "batchSeq", 1, "observations", List.of(), "icons", icons));
        assertThat(iconBatch.status()).as(iconBatch.body()).isEqualTo(200);
        assertThat(iconBatch.json().get("dropped").asInt()).isEqualTo(withOutOfScope ? 1 : 0);
        Response done = agents().as(agent).post(base + "/complete", Map.of("schemaVersion", 1, "totalBatches", 2,
                "outcome", "COMPLETED", "warnings", List.of()));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }

    private static Map<String, Object> icon(String ip, byte[] data) {
        return Map.of("ip", ip, "origin", "UPNP", "contentType", "image/png", "width", 120, "height", 120,
                "data", Base64.getEncoder().encodeToString(data), "observedAt", Instant.now().toString());
    }

    private static byte[] png(int w, int h) throws Exception {
        return encode(new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB), "png");
    }

    private static byte[] jpeg(int w, int h) throws Exception {
        return encode(new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB), "jpeg");
    }

    private static byte[] encode(BufferedImage img, String format) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, format, out);
        return out.toByteArray();
    }
}
