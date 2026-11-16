package com.shsc.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/** Creates real accounts through the public API (register → e-mail link → verify → login). */
public class TestAccounts {

    public static final String PASSWORD = "Lungo-e-sicuro-42!";

    public record Account(String email, String password, ApiClient client, String accessToken, UUID tenantId,
            UUID userId) {

        public ApiClient api() {
            return client.bearer(accessToken);
        }
    }

    private final Supplier<ApiClient> clients;
    private final Mailbox mailbox;

    public TestAccounts(Supplier<ApiClient> clients, Mailbox mailbox) {
        this.clients = clients;
        this.mailbox = mailbox;
    }

    public static String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
    }

    public Account individual() {
        return create(uniqueEmail("b2c"), "INDIVIDUAL", null);
    }

    public Account business(String organization) {
        return create(uniqueEmail("b2b"), "BUSINESS", organization);
    }

    public Account create(String email, String type, String organization) {
        ApiClient client = clients.get();
        Map<String, Object> body = new java.util.HashMap<>(Map.of("email", email, "password", PASSWORD,
                "displayName", "Test User", "locale", "it", "accountType", type));
        if (organization != null) {
            body.put("organizationName", organization);
        }
        assertThat(client.post("/api/v1/auth/register", body).status()).isEqualTo(202);
        verify(client, email, 1);
        return login(client, email, PASSWORD);
    }

    public void verify(ApiClient client, String email, int mailNumber) {
        String token = Mailbox.token(mailbox.await(email, mailNumber)).orElseThrow();
        assertThat(client.post("/api/v1/auth/verify-email", Map.of("token", token)).status()).isEqualTo(204);
    }

    public Account login(ApiClient client, String email, String password) {
        ApiClient.Response login = client.post("/api/v1/auth/login",
                Map.of("email", email, "password", password, "deviceLabel", "test"));
        assertThat(login.status()).as(login.body()).isEqualTo(200);
        String token = login.text("accessToken");
        ApiClient.Response me = client.bearer(token).get("/api/v1/me");
        assertThat(me.status()).isEqualTo(200);
        UUID tenantId = UUID.fromString(me.json().get("tenant").get("id").asString());
        UUID userId = UUID.fromString(me.text("id"));
        return new Account(email, password, client, token, tenantId, userId);
    }
}
