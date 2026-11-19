package com.shsc.alerts.push;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;

import com.shsc.alerts.AlertJobs;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts;
import com.shsc.support.TestAccounts.Account;
import com.shsc.support.TestAgents;
import com.shsc.support.TestAgents.EnrolledAgent;

/**
 * Backend of the mobile app (Milestone 14): login with the refresh token in the body (no cookie,
 * no CSRF), rotation and reuse detection, push registrations bound to the session, PUSH deliveries
 * through the (mocked) FCM gateway, invalid tokens removed, logout stops the pushes, isolation.
 * [MOCK] tokens and devices: nothing is sent to Firebase and nothing is scanned.
 */
class MobileApiTest extends IntegrationTest {

    private static final String TOKEN_A = "MOCK-fcm-token-A_" + "a".repeat(40);
    private static final String TOKEN_B = "MOCK-fcm-token-B_" + "b".repeat(40);

    @Autowired
    private AlertJobs jobs;

    @Autowired
    private PushDeviceRepository devices;

    @Autowired
    private TenantScope tenantScope;

    @AfterEach
    void resetPush() {
        reset(push);
    }

    private static Response mobileLogin(ApiClient client, Account account) {
        return client.withoutCsrf().post("/api/v1/auth/mobile/login",
                Map.of("email", account.email(), "password", TestAccounts.PASSWORD, "deviceLabel", "Pixel MOCK"));
    }

    @Test
    void mobileSessionsUseBodyTokensWithRotationAndReuseDetection() {
        Account owner = accounts().individual();
        ApiClient app = client();

        Response login = mobileLogin(app, owner);
        assertThat(login.status()).as(login.body()).isEqualTo(200);
        assertThat(login.setCookies()).noneMatch(c -> c.startsWith("shsc_rt="));
        String access = login.text("accessToken");
        String refresh = login.text("refreshToken");
        assertThat(refresh).isNotBlank();
        assertThat(login.text("refreshExpiresAt")).isNotBlank();
        assertThat(client().bearer(access).get("/api/v1/me").status()).isEqualTo(200);

        // wrong password: same generic 401 as the web login
        assertThat(app.withoutCsrf().post("/api/v1/auth/mobile/login", Map.of("email", owner.email(),
                "password", "sbagliata-MOCK")).status()).isEqualTo(401);

        // rotation: a new pair, the old refresh token is consumed
        Response rotated = app.withoutCsrf().post("/api/v1/auth/mobile/refresh", Map.of("refreshToken", refresh));
        assertThat(rotated.status()).as(rotated.body()).isEqualTo(200);
        String refresh2 = rotated.text("refreshToken");
        assertThat(refresh2).isNotEqualTo(refresh);
        assertThat(rotated.text("sessionId")).isEqualTo(login.text("sessionId"));

        // reuse of the consumed token: rejected and the whole session is revoked
        assertThat(app.withoutCsrf().post("/api/v1/auth/mobile/refresh", Map.of("refreshToken", refresh)).status())
                .isEqualTo(401);
        assertThat(app.withoutCsrf().post("/api/v1/auth/mobile/refresh", Map.of("refreshToken", refresh2)).status())
                .isEqualTo(401);
        assertThat(app.withoutCsrf().post("/api/v1/auth/mobile/refresh", Map.of()).status()).isEqualTo(400);

        // the web cookie endpoints still require the CSRF header
        assertThat(app.withoutCsrf().post("/api/v1/auth/refresh", null).status()).isEqualTo(403);
    }

    @Test
    void pushRegistrationsReceiveAlertsUntilLogout() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa push MOCK");
        String network = Fixtures.createNetwork(owner, home, "192.168.74.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        TestAgents agents = new TestAgents(this::client, json);
        EnrolledAgent agent = agents.enroll(owner, home);

        ApiClient app = client();
        Response login = mobileLogin(app, owner);
        ApiClient phone = client().bearer(login.text("accessToken"));

        // registration: validated, token never returned, bound to the current session
        assertThat(phone.post("/api/v1/push-devices", Map.of("token", "short", "platform", "ANDROID")).status())
                .isEqualTo(400);
        assertThat(phone.post("/api/v1/push-devices", Map.of("token", TOKEN_A, "platform", "WINDOWS")).status())
                .isEqualTo(400);
        Response a = phone.post("/api/v1/push-devices", Map.of("token", TOKEN_A, "platform", "ANDROID", "locale", "en"));
        assertThat(a.status()).as(a.body()).isEqualTo(201);
        assertThat(a.body()).doesNotContain(TOKEN_A);
        assertThat(a.json().get("currentSession").asBoolean()).isTrue();
        Response again = phone.post("/api/v1/push-devices", Map.of("token", TOKEN_A, "platform", "ANDROID", "locale", "en"));
        assertThat(again.text("id")).isEqualTo(a.text("id")); // same installation: same registration
        assertThat(phone.post("/api/v1/push-devices", Map.of("token", TOKEN_B, "platform", "IOS")).status())
                .isEqualTo(201);
        assertThat(phone.get("/api/v1/push-devices").json().size()).isEqualTo(2);

        // another tenant neither sees nor removes them
        Account other = accounts().individual();
        assertThat(other.api().get("/api/v1/push-devices").json().size()).isZero();
        assertThat(other.api().delete("/api/v1/push-devices/" + a.text("id")).status()).isEqualTo(404);

        // FCM enabled: a failed scan raises SCAN_FAILED, pushed in the device language; B is no longer valid
        when(push.enabled()).thenReturn(true);
        when(push.send(eq(TOKEN_A), anyString(), anyString(), any())).thenReturn(PushGateway.Result.SENT);
        when(push.send(eq(TOKEN_B), anyString(), anyString(), any())).thenReturn(PushGateway.Result.INVALID_TOKEN);
        failedScan(owner, home, agents, agent);
        assertThat(jobs.dispatchPushes()).isEqualTo(1);
        ArgumentCaptor<String> title = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> data = ArgumentCaptor.forClass(Map.class);
        verify(push).send(eq(TOKEN_A), title.capture(), eq("Casa push MOCK"), data.capture());
        assertThat(title.getValue()).isNotBlank().doesNotContain("192.168.");
        assertThat(data.getValue()).containsEntry("type", "SCAN_FAILED").containsEntry("homeId", home)
                .containsKeys("alertId").hasSize(3);
        assertThat(phone.get("/api/v1/push-devices").json().size()).isEqualTo(1); // B removed
        assertThat(jobs.dispatchPushes()).isZero(); // already sent

        // logout: the session's registrations no longer receive anything
        assertThat(app.withoutCsrf().post("/api/v1/auth/mobile/logout",
                Map.of("refreshToken", login.text("refreshToken"))).status()).isEqualTo(204);
        UUID userId = owner.userId();
        List<?> active = tenantScope.callAs(owner.tenantId(), () -> devices.activeOfUser(userId, Instant.now()));
        assertThat(active).isEmpty();
    }

    @Test
    void withoutFcmNoPushDeliveryIsCreated() throws Exception {
        Account owner = accounts().individual();
        String home = Fixtures.createHome(owner, "Casa senza push MOCK");
        String network = Fixtures.createNetwork(owner, home, "192.168.75.0/24");
        assertThat(owner.api().post("/api/v1/networks/" + network + "/authorization",
                Map.of("attestation", true, "attestationVersion", "1")).status()).isEqualTo(200);
        TestAgents agents = new TestAgents(this::client, json);
        EnrolledAgent agent = agents.enroll(owner, home);
        ApiClient app = client();
        ApiClient phone = client().bearer(mobileLogin(app, owner).text("accessToken"));
        Response registered = phone.post("/api/v1/push-devices", Map.of("token", TOKEN_A, "platform", "ANDROID"));
        assertThat(registered.json().get("pushEnabled").asBoolean()).isFalse();

        failedScan(owner, home, agents, agent);
        assertThat(jobs.dispatchPushes()).isZero();
        verify(push, never()).send(anyString(), anyString(), anyString(), any());
    }

    private static void failedScan(Account owner, String home, TestAgents agents, EnrolledAgent agent) {
        assertThat(agents.as(agent).post("/api/v1/agent/heartbeat", Map.of("schemaVersion", 1,
                "agentVersion", "0.14.0", "uptimeSeconds", 5, "interfacesHash", "f".repeat(64), "queueDepth", 0,
                "capabilities", Map.of("privileged", false, "arp", "os_api", "icmp", "os_api", "warnings", List.of())))
                .status()).isEqualTo(200);
        Response created = owner.api().post("/api/v1/homes/" + home + "/scans", Map.of("profile", "QUICK"));
        assertThat(created.status()).as(created.body()).isEqualTo(202);
        String scan = created.text("id");
        assertThat(agents.as(agent).post("/api/v1/agent/scans/" + scan + "/ack", null).status()).isEqualTo(200);
        Response done = agents.as(agent).post("/api/v1/agent/scans/" + scan + "/complete", Map.of("schemaVersion", 1,
                "totalBatches", 0, "outcome", "FAILED", "warnings", List.of(), "errorCode", "MOCK_ERROR"));
        assertThat(done.status()).as(done.body()).isEqualTo(200);
    }
}
