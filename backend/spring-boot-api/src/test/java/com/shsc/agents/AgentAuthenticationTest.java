package com.shsc.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;

/**
 * Agent authentication: one-time expiring enrollment token, Ed25519 identity, signed
 * assertions with anti-replay, short-lived opaque tokens, revocation, key rotation,
 * agent ↔ home binding, strict separation from user JWTs.
 */
class AgentAuthenticationTest extends IntegrationTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    JdbcClient jdbc;

    @Autowired
    TransactionTemplate tx;

    @Autowired
    TenantScope tenantScope;

    record Enrolled(Account owner, String homeId, String agentId, KeyPair keys) {
    }

    @Test
    void enrollmentTokenIsOneTimeAndShownOnlyOnce() throws Exception {
        Account owner = accounts().individual();
        String homeId = home(owner);
        Response created = owner.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null);
        assertThat(created.status()).isEqualTo(201);
        String token = created.text("token");
        assertThat(token).startsWith("shsc_enr_");

        Response list = owner.api().get("/api/v1/homes/" + homeId + "/agent-enrollment-tokens");
        assertThat(list.body()).doesNotContain(token).contains("ACTIVE");

        KeyPair keys = newKeys();
        Response enrolled = client().post("/api/v1/agent/enroll", enrollBody(token, keys));
        assertThat(enrolled.status()).as(enrolled.body()).isEqualTo(201);
        assertThat(enrolled.text("homeId")).isEqualTo(homeId);

        Response reused = client().post("/api/v1/agent/enroll", enrollBody(token, newKeys()));
        assertThat(reused.status()).isEqualTo(401);
        assertThat(reused.text("code")).isEqualTo("INVALID_ENROLLMENT_TOKEN");
        assertThat(owner.api().get("/api/v1/homes/" + homeId + "/agent-enrollment-tokens").body()).contains("USED");
    }

    @Test
    void expiredOrRevokedEnrollmentTokensAreRejected() throws Exception {
        Account owner = accounts().individual();
        String homeId = home(owner);

        Response expiring = owner.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null);
        tenantScope.runAs(owner.tenantId(), () -> tx.executeWithoutResult(s -> jdbc.sql(
                "UPDATE agent_enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE id = :id")
                .param("id", UUID.fromString(expiring.text("id"))).update()));
        assertThat(client().post("/api/v1/agent/enroll", enrollBody(expiring.text("token"), newKeys())).status())
                .isEqualTo(401);

        Response revoked = owner.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null);
        assertThat(owner.api().delete("/api/v1/agent-enrollment-tokens/" + revoked.text("id")).status()).isEqualTo(204);
        assertThat(client().post("/api/v1/agent/enroll", enrollBody(revoked.text("token"), newKeys())).status())
                .isEqualTo(401);

        assertThat(client().post("/api/v1/agent/enroll", enrollBody("shsc_enr_invented", newKeys())).status())
                .isEqualTo(401);
    }

    @Test
    void invalidPublicKeysAreRejected() throws Exception {
        Account owner = accounts().individual();
        String token = owner.api().post("/api/v1/homes/" + home(owner) + "/agent-enrollment-tokens", null).text("token");
        Map<String, Object> body = new LinkedHashMap<>(enrollBody(token, newKeys()));
        body.put("publicKey", B64URL.encodeToString(new byte[16]));
        Response response = client().post("/api/v1/agent/enroll", body);
        assertThat(response.status()).isEqualTo(400);
        assertThat(response.text("code")).isEqualTo("INVALID_PUBLIC_KEY");
    }

    @Test
    void signedAssertionGivesAShortLivedTokenBoundToTheHome() throws Exception {
        Enrolled agent = enroll();
        Response token = client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(agent.keys(), agent.agentId(), "shsc-agent-token")));
        assertThat(token.status()).as(token.body()).isEqualTo(200);
        assertThat(token.text("accessToken")).startsWith("shsc_at_");
        assertThat(token.json().get("expiresIn").asLong()).isEqualTo(600);

        Response session = client().bearer(token.text("accessToken")).get("/api/v1/agent/session");
        assertThat(session.status()).isEqualTo(200);
        assertThat(session.text("agentId")).isEqualTo(agent.agentId());
        assertThat(session.text("homeId")).isEqualTo(agent.homeId());
        assertThat(session.text("homeName")).isEqualTo("Casa agent");
    }

    @Test
    void assertionsCannotBeReplayedForgedOrLongLived() throws Exception {
        Enrolled agent = enroll();
        String assertion = assertion(agent.keys(), agent.agentId(), "shsc-agent-token");
        assertThat(client().post("/api/v1/agent/token", Map.of("assertion", assertion)).status()).isEqualTo(200);
        assertThat(client().post("/api/v1/agent/token", Map.of("assertion", assertion)).status()).isEqualTo(401);

        // signed with another key
        assertThat(client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(newKeys(), agent.agentId(), "shsc-agent-token"))).status()).isEqualTo(401);
        // wrong audience
        assertThat(client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(agent.keys(), agent.agentId(), "other"))).status()).isEqualTo(401);
        // lifetime above 60 s
        long now = Instant.now().getEpochSecond();
        assertThat(client().post("/api/v1/agent/token", Map.of("assertion", sign(agent.keys(), Map.of("iss",
                agent.agentId(), "sub", agent.agentId(), "aud", "shsc-agent-token", "iat", now, "exp", now + 3600,
                "jti", UUID.randomUUID().toString())))).status()).isEqualTo(401);
        // expired
        assertThat(client().post("/api/v1/agent/token", Map.of("assertion", sign(agent.keys(), Map.of("iss",
                agent.agentId(), "sub", agent.agentId(), "aud", "shsc-agent-token", "iat", now - 300, "exp", now - 250,
                "jti", UUID.randomUUID().toString())))).status()).isEqualTo(401);
        // unsigned
        String unsigned = B64URL.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + assertion.split("\\.")[1] + ".";
        assertThat(client().post("/api/v1/agent/token", Map.of("assertion", unsigned)).status()).isEqualTo(401);
    }

    @Test
    void userAndAgentCredentialsAreNotInterchangeable() throws Exception {
        Enrolled agent = enroll();
        String agentToken = agentToken(agent);

        assertThat(client().bearer(agent.owner().accessToken()).get("/api/v1/agent/session").status()).isEqualTo(401);
        assertThat(client().bearer(agentToken).get("/api/v1/me").status()).isEqualTo(401);
        assertThat(client().bearer(agentToken).get("/api/v1/homes").status()).isEqualTo(401);
        assertThat(client().get("/api/v1/agent/session").status()).isEqualTo(401);
    }

    @Test
    void revokedAgentIsLockedOutImmediately() throws Exception {
        Enrolled agent = enroll();
        String agentToken = agentToken(agent);

        Response revoke = agent.owner().api().post("/api/v1/agents/" + agent.agentId() + "/revoke",
                Map.of("reason", "PC dismesso"));
        assertThat(revoke.status()).isEqualTo(200);
        assertThat(revoke.text("status")).isEqualTo("REVOKED");

        Response session = client().bearer(agentToken).get("/api/v1/agent/session");
        assertThat(session.status()).isEqualTo(401);
        assertThat(session.text("code")).isEqualTo("AGENT_REVOKED");
        Response token = client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(agent.keys(), agent.agentId(), "shsc-agent-token")));
        assertThat(token.status()).isEqualTo(401);
        assertThat(token.text("code")).isEqualTo("AGENT_REVOKED");

        assertThat(agent.owner().api().get("/api/v1/audit-logs").body()).contains("AGENT_ENROLLED")
                .contains("AGENT_REVOKED").contains("AGENT_ENROLLMENT_TOKEN_CREATED");
    }

    @Test
    void keyRotationRetiresTheOldKey() throws Exception {
        Enrolled agent = enroll();
        String agentToken = agentToken(agent);
        KeyPair next = newKeys();

        // proof signed with a key that is not the announced one
        Response bad = client().bearer(agentToken).post("/api/v1/agent/credentials/rotate", Map.of(
                "publicKey", raw(next), "proof", assertion(newKeys(), agent.agentId(), "shsc-agent-rotate")));
        assertThat(bad.status()).isEqualTo(400);

        Response rotated = client().bearer(agentToken).post("/api/v1/agent/credentials/rotate", Map.of(
                "publicKey", raw(next), "proof", assertion(next, agent.agentId(), "shsc-agent-rotate")));
        assertThat(rotated.status()).as(rotated.body()).isEqualTo(200);

        // tokens of the old key are revoked, the old key cannot mint new ones
        assertThat(client().bearer(agentToken).get("/api/v1/agent/session").status()).isEqualTo(401);
        assertThat(client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(agent.keys(), agent.agentId(), "shsc-agent-token"))).status())
                .isEqualTo(401);
        Response withNewKey = client().post("/api/v1/agent/token",
                Map.of("assertion", assertion(next, agent.agentId(), "shsc-agent-token")));
        assertThat(withNewKey.status()).isEqualTo(200);
        assertThat(client().bearer(withNewKey.text("accessToken")).get("/api/v1/agent/session").status())
                .isEqualTo(200);
    }

    @Test
    void agentsOfOtherTenantsCannotBeManaged() throws Exception {
        Enrolled agent = enroll();
        Account stranger = accounts().individual();
        assertThat(stranger.api().get("/api/v1/agents/" + agent.agentId()).status()).isEqualTo(404);
        assertThat(stranger.api().post("/api/v1/agents/" + agent.agentId() + "/revoke", null).status()).isEqualTo(404);
        assertThat(agent.owner().api().get("/api/v1/agents/" + agent.agentId()).text("status")).isEqualTo("ACTIVE");
    }

    // ------------------------------------------------------------------ helpers

    private Enrolled enroll() throws GeneralSecurityException {
        Account owner = accounts().individual();
        String homeId = home(owner);
        String token = owner.api().post("/api/v1/homes/" + homeId + "/agent-enrollment-tokens", null).text("token");
        KeyPair keys = newKeys();
        Response enrolled = client().post("/api/v1/agent/enroll", enrollBody(token, keys));
        assertThat(enrolled.status()).as(enrolled.body()).isEqualTo(201);
        return new Enrolled(owner, homeId, enrolled.text("agentId"), keys);
    }

    private String agentToken(Enrolled agent) throws GeneralSecurityException {
        ApiClient anonymous = client();
        Response token = anonymous.post("/api/v1/agent/token",
                Map.of("assertion", assertion(agent.keys(), agent.agentId(), "shsc-agent-token")));
        assertThat(token.status()).isEqualTo(200);
        return token.text("accessToken");
    }

    private String home(Account owner) {
        return owner.api().post("/api/v1/homes", Map.of("name", "Casa agent")).text("id");
    }

    private static Map<String, Object> enrollBody(String token, KeyPair keys) {
        return Map.of("enrollmentToken", token, "publicKey", raw(keys), "hostname", "pc-salotto",
                "os", "linux", "arch", "amd64", "agentVersion", "0.3.0-test");
    }

    private static KeyPair newKeys() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String raw(KeyPair keys) {
        byte[] x509 = keys.getPublic().getEncoded();
        return B64URL.encodeToString(Arrays.copyOfRange(x509, x509.length - 32, x509.length));
    }

    private String assertion(KeyPair keys, String agentId, String audience) throws GeneralSecurityException {
        long now = Instant.now().getEpochSecond();
        return sign(keys, Map.of("iss", agentId, "sub", agentId, "aud", audience, "iat", now, "exp", now + 60,
                "jti", UUID.randomUUID().toString()));
    }

    private String sign(KeyPair keys, Map<String, Object> claims) throws GeneralSecurityException {
        String header = B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64URL.encodeToString(json.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.getPrivate());
        signer.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        return header + "." + payload + "." + B64URL.encodeToString(signer.sign());
    }
}
