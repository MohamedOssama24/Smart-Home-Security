package com.shsc.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import com.shsc.support.ApiClient.Response;
import com.shsc.support.TestAccounts.Account;

import tools.jackson.databind.json.JsonMapper;

/**
 * Plays the role of a real agent in integration tests: Ed25519 key pair, enrollment with a
 * one-time token, signed assertion and access token, exactly as the Go agent does.
 */
public final class TestAgents {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    /** An enrolled agent with its key and a valid access token. */
    public record EnrolledAgent(String agentId, String homeId, KeyPair keys, String accessToken) {
    }

    private final Supplier<ApiClient> clients;
    private final JsonMapper json;

    public TestAgents(Supplier<ApiClient> clients, JsonMapper json) {
        this.clients = clients;
        this.json = json;
    }

    /** Creates an enrollment token for the home (as the owner) and returns the clear token. */
    public static String enrollmentToken(Account owner, String homeId) {
        Response created = owner.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null);
        assertThat(created.status()).as(created.body()).isEqualTo(201);
        return created.text("token");
    }

    /** Enrolls a new agent with the token; returns the raw response. */
    public Response tryEnroll(String token, KeyPair keys) {
        return clients.get().post("/api/v1/agent/enroll", Map.of("enrollmentToken", token, "publicKey", raw(keys),
                "hostname", "pc-test", "os", "linux", "arch", "amd64", "agentVersion", "0.5.0-test"));
    }

    /** Enrolls a new agent in the home and logs it in. */
    public EnrolledAgent enroll(Account owner, String homeId) throws GeneralSecurityException {
        KeyPair keys = newKeys();
        Response enrolled = tryEnroll(enrollmentToken(owner, homeId), keys);
        assertThat(enrolled.status()).as(enrolled.body()).isEqualTo(201);
        String agentId = enrolled.text("agentId");
        return new EnrolledAgent(agentId, homeId, keys, login(agentId, keys));
    }

    /** Exchanges a fresh signed assertion for an access token. */
    public String login(String agentId, KeyPair keys) throws GeneralSecurityException {
        Response token = clients.get().post("/api/v1/agent/token", Map.of("assertion", assertion(keys, agentId)));
        assertThat(token.status()).as(token.body()).isEqualTo(200);
        return token.text("accessToken");
    }

    public ApiClient as(EnrolledAgent agent) {
        return clients.get().bearer(agent.accessToken());
    }

    public static KeyPair newKeys() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String raw(KeyPair keys) {
        byte[] x509 = keys.getPublic().getEncoded();
        return B64URL.encodeToString(Arrays.copyOfRange(x509, x509.length - 32, x509.length));
    }

    private String assertion(KeyPair keys, String agentId) throws GeneralSecurityException {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = Map.of("iss", agentId, "sub", agentId, "aud", "shsc-agent-token", "iat", now,
                "exp", now + 60, "jti", UUID.randomUUID().toString());
        String header = B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64URL.encodeToString(json.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.getPrivate());
        signer.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return header + "." + payload + "." + B64URL.encodeToString(signer.sign());
    }
}
