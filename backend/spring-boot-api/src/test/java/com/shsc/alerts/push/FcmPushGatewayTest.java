package com.shsc.alerts.push;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * FCM HTTP v1 client against a local [MOCK] server playing both Google OAuth and FCM: signed
 * service-account assertion, cached access token, message format, error mapping. No request
 * leaves the machine; the key pair is generated for the test.
 */
class FcmPushGatewayTest {

    private final JsonMapper json = JsonMapper.builder().build();
    private final List<String> calls = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private KeyPair keys;
    private volatile int sendStatus = 200;
    private volatile String sendBody = "{\"name\":\"projects/mock/messages/1\"}";
    private volatile JsonNode lastMessage;

    @TempDir
    Path dir;

    @BeforeEach
    void start() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", this::token);
        server.createContext("/v1/projects/mock-project/messages:send", this::send);
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private URI base() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    private FcmPushGateway gateway() throws IOException {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(keys.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
        Path file = dir.resolve("service-account-MOCK.json");
        Files.writeString(file, json.writeValueAsString(Map.of("type", "service_account",
                "client_email", "push@mock-project.iam.gserviceaccount.com", "private_key", pem,
                "token_uri", base().resolve("/token").toString())));
        return new FcmPushGateway(json, Clock.systemUTC(), "mock-project", file.toString(), base());
    }

    private void token(HttpExchange exchange) throws IOException {
        calls.add("token");
        String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String assertion = URLDecoder.decode(form.replaceAll(".*assertion=", ""), StandardCharsets.UTF_8);
        String[] parts = assertion.split("\\.");
        boolean valid;
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(keys.getPublic());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            JsonNode claims = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
            valid = verifier.verify(Base64.getUrlDecoder().decode(parts[2]))
                    && form.startsWith("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
                    && FcmPushGateway.SCOPE.equals(claims.path("scope").asString())
                    && claims.path("iss").asString().startsWith("push@");
        } catch (Exception e) {
            valid = false;
        }
        reply(exchange, valid ? 200 : 400, valid ? "{\"access_token\":\"MOCK-access\",\"expires_in\":3600}" : "{}");
    }

    private void send(HttpExchange exchange) throws IOException {
        calls.add("send");
        if (!"Bearer MOCK-access".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
            reply(exchange, 401, "{}");
            return;
        }
        lastMessage = json.readTree(exchange.getRequestBody().readAllBytes()).path("message");
        reply(exchange, sendStatus, sendBody);
    }

    private static void reply(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Test
    void disabledWithoutConfiguration() {
        FcmPushGateway gateway = new FcmPushGateway(json, Clock.systemUTC(), "", "", base());
        assertThat(gateway.enabled()).isFalse();
        assertThat(gateway.send("t", "x", "y", Map.of())).isEqualTo(PushGateway.Result.FAILED);
        assertThat(calls).isEmpty();
    }

    @Test
    void sendsWithSignedAssertionAndCachedToken() throws Exception {
        FcmPushGateway gateway = gateway();
        assertThat(gateway.enabled()).isTrue();
        assertThat(gateway.send("MOCK-device", "Titolo", "Casa MOCK", Map.of("type", "SCAN_FAILED")))
                .isEqualTo(PushGateway.Result.SENT);
        assertThat(lastMessage.path("token").asString()).isEqualTo("MOCK-device");
        assertThat(lastMessage.path("notification").path("title").asString()).isEqualTo("Titolo");
        assertThat(lastMessage.path("notification").path("body").asString()).isEqualTo("Casa MOCK");
        assertThat(lastMessage.path("data").path("type").asString()).isEqualTo("SCAN_FAILED");
        assertThat(gateway.send("MOCK-device", "Titolo", "Casa MOCK", Map.of())).isEqualTo(PushGateway.Result.SENT);
        assertThat(calls).containsExactly("token", "send", "send"); // access token reused
    }

    @Test
    void mapsErrors() throws Exception {
        FcmPushGateway gateway = gateway();
        sendStatus = 404;
        sendBody = "{\"error\":{\"status\":\"NOT_FOUND\",\"details\":[{\"errorCode\":\"UNREGISTERED\"}]}}";
        assertThat(gateway.send("MOCK-old", "t", "b", Map.of())).isEqualTo(PushGateway.Result.INVALID_TOKEN);
        sendStatus = 400;
        sendBody = "{\"error\":{\"status\":\"INVALID_ARGUMENT\"}}";
        assertThat(gateway.send("MOCK-bad", "t", "b", Map.of())).isEqualTo(PushGateway.Result.INVALID_TOKEN);
        sendStatus = 503;
        sendBody = "{\"error\":{\"status\":\"UNAVAILABLE\"}}";
        assertThat(gateway.send("MOCK-ok", "t", "b", Map.of())).isEqualTo(PushGateway.Result.FAILED);
    }
}
