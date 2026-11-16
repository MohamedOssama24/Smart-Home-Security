package com.shsc.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.support.ApiClient.Response;
import com.shsc.support.IntegrationTest;

/**
 * HTTP surface: health probes public and minimal, actuator and API docs closed, API
 * protected by default with Problem Details errors, CORS closed to foreign origins.
 */
class HttpSurfaceTest extends IntegrationTest {

    @Test
    void healthIsUpAndDoesNotLeakDetails() {
        Response response = client().get("/actuator/health");

        assertThat(response.status()).isEqualTo(200);
        assertThat(response.body()).contains("\"status\":\"UP\"");
        assertThat(response.body()).doesNotContain("db").doesNotContain("diskSpace");
    }

    @Test
    void readinessAndLivenessProbesAreExposed() {
        assertThat(client().get("/actuator/health/readiness").status()).isEqualTo(200);
        assertThat(client().get("/actuator/health/liveness").status()).isEqualTo(200);
    }

    @Test
    void sensitiveActuatorEndpointsAreNotExposed() {
        for (String path : new String[] {"/actuator/env", "/actuator/beans", "/actuator/configprops",
                "/actuator/heapdump", "/actuator/loggers", "/actuator/mappings"}) {
            assertThat(client().get(path).status()).as(path).isEqualTo(404);
        }
    }

    @Test
    void apiDocsAreDisabledByDefault() {
        assertThat(client().get("/api/v1/openapi.json").status()).isEqualTo(404);
    }

    @Test
    void apiRequiresAuthenticationAndAnswersWithProblemDetails() {
        Response response = client().get("/api/v1/does-not-exist");

        assertThat(response.status()).isEqualTo(401);
        assertThat(response.header("Content-Type")).hasValueSatisfying(
                type -> assertThat(type).startsWith("application/problem+json"));
        assertThat(response.header("WWW-Authenticate")).hasValue("Bearer");
        assertThat(response.text("code")).isEqualTo("UNAUTHENTICATED");
        assertThat(response.body()).doesNotContain("Exception").doesNotContain("trace");
    }

    @Test
    void unknownApiPathOfAnAuthenticatedUserIsNotFound() {
        var account = accounts().individual();
        Response response = account.api().get("/api/v1/does-not-exist");

        assertThat(response.status()).isEqualTo(404);
        assertThat(response.header("Content-Type")).hasValueSatisfying(
                type -> assertThat(type).startsWith("application/problem+json"));
    }

    @Test
    void apiResponsesAreNotCached() {
        Response response = client().get("/api/v1/auth/csrf");
        assertThat(response.header("Cache-Control")).hasValueSatisfying(v -> assertThat(v).contains("no-store"));
    }

    @Test
    void crossOriginRequestsGetNoCorsGrant() {
        Response preflight = client().send("OPTIONS", "/api/v1/auth/login", null, Map.of(
                "Origin", "https://evil.example", "Access-Control-Request-Method", "POST"));
        assertThat(preflight.header("Access-Control-Allow-Origin")).isEmpty();
        assertThat(preflight.header("Access-Control-Allow-Credentials")).isEmpty();
    }

    @Test
    void unknownNonApiPathsAreDenied() {
        assertThat(client().get("/internal/anything").status()).isIn(401, 403);
    }
}
