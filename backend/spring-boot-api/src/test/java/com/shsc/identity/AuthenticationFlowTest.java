package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.mail.SimpleMailMessage;

import com.shsc.support.ApiClient;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.IntegrationTest;
import com.shsc.support.Mailbox;
import com.shsc.support.TestAccounts;
import com.shsc.support.TestAccounts.Account;

/** End-to-end user authentication: registration, verification, login, refresh, logout. */
class AuthenticationFlowTest extends IntegrationTest {

    private static final String REFRESH_COOKIE = "shsc_rt";

    @Test
    void registrationRequiresEmailVerificationBeforeLogin() {
        ApiClient client = client();
        String email = TestAccounts.uniqueEmail("flow");

        Response register = client.post("/api/v1/auth/register", Map.of("email", email, "password",
                TestAccounts.PASSWORD, "displayName", "Mario Rossi", "locale", "it", "accountType", "INDIVIDUAL"));
        assertThat(register.status()).isEqualTo(202);

        SimpleMailMessage mail = mailbox().await(email, 1);
        assertThat(mail.getSubject()).contains("Conferma");
        assertThat(mail.getText()).contains("https://shsc.test/verify-email#token=shsc_et_");

        Response early = client.post("/api/v1/auth/login", Map.of("email", email, "password", TestAccounts.PASSWORD));
        assertThat(early.status()).isEqualTo(403);
        assertThat(early.text("code")).isEqualTo("EMAIL_NOT_VERIFIED");

        String token = Mailbox.token(mail).orElseThrow();
        assertThat(client.post("/api/v1/auth/verify-email", Map.of("token", token)).status()).isEqualTo(204);
        // one-time token
        assertThat(client.post("/api/v1/auth/verify-email", Map.of("token", token)).text("code"))
                .isEqualTo("INVALID_TOKEN");

        Response login = client.post("/api/v1/auth/login", Map.of("email", email.toUpperCase(), "password",
                TestAccounts.PASSWORD));
        assertThat(login.status()).isEqualTo(200);
        assertThat(login.text("tokenType")).isEqualTo("Bearer");
        assertThat(login.json().get("expiresIn").asLong()).isEqualTo(900);
        assertThat(login.body()).doesNotContain("shsc_rt_");

        Response me = client.bearer(login.text("accessToken")).get("/api/v1/me");
        assertThat(me.status()).isEqualTo(200);
        assertThat(me.text("email")).isEqualTo(email);
        assertThat(me.text("status")).isEqualTo("ACTIVE");
        assertThat(me.json().get("tenant").get("type").asString()).isEqualTo("INDIVIDUAL");
        assertThat(me.json().get("permissions").toString()).contains("home:write").doesNotContain("role:manage");
    }

    @Test
    void refreshCookieIsHttpOnlySecureStrictAndScopedToAuthPath() {
        Account account = accounts().individual();
        ApiClient client = account.client();
        Response login = client.post("/api/v1/auth/login", Map.of("email", account.email(), "password",
                account.password()));

        String cookie = login.setCookie(REFRESH_COOKIE).orElseThrow();
        assertThat(cookie).contains("HttpOnly").contains("Secure").contains("SameSite=Strict")
                .contains("Path=/api/v1/auth").contains("Max-Age=");
        assertThat(client.cookie(REFRESH_COOKIE)).startsWith("shsc_rt_");
    }

    @Test
    void refreshRotatesTheTokenAndDetectsReuse() {
        Account account = accounts().individual();
        ApiClient client = account.client();
        String first = client.cookie(REFRESH_COOKIE);

        Response refreshed = client.post("/api/v1/auth/refresh", null);
        assertThat(refreshed.status()).isEqualTo(200);
        String second = client.cookie(REFRESH_COOKIE);
        assertThat(second).isNotEqualTo(first);
        String newAccess = refreshed.text("accessToken");
        assertThat(client.bearer(newAccess).get("/api/v1/me").status()).isEqualTo(200);

        // an attacker replays the old (already rotated) refresh token
        ApiClient attacker = client();
        attacker.setCookie(REFRESH_COOKIE, first);
        Response reuse = attacker.post("/api/v1/auth/refresh", null);
        assertThat(reuse.status()).isEqualTo(401);
        assertThat(reuse.text("code")).isEqualTo("INVALID_REFRESH_TOKEN");

        // the whole session is revoked: the legitimate token and the access token stop working
        assertThat(client.post("/api/v1/auth/refresh", null).status()).isEqualTo(401);
        assertThat(client.bearer(newAccess).get("/api/v1/me").status()).isEqualTo(401);

        Response audit = accounts().login(client(), account.email(), account.password()).api()
                .get("/api/v1/audit-logs");
        assertThat(audit.body()).contains("REFRESH_TOKEN_REUSE");
    }

    @Test
    void logoutRevokesTheSessionAndClearsTheCookie() {
        Account account = accounts().individual();
        ApiClient client = account.client();
        String refresh = client.cookie(REFRESH_COOKIE);

        Response logout = client.post("/api/v1/auth/logout", null);
        assertThat(logout.status()).isEqualTo(204);
        assertThat(logout.setCookie(REFRESH_COOKIE).orElseThrow()).contains("Max-Age=0");

        assertThat(client.bearer(account.accessToken()).get("/api/v1/me").status()).isEqualTo(401);
        ApiClient replay = client();
        replay.setCookie(REFRESH_COOKIE, refresh);
        assertThat(replay.post("/api/v1/auth/refresh", null).status()).isEqualTo(401);
    }

    @Test
    void refreshWithoutCookieIsRejected() {
        Response response = client().post("/api/v1/auth/refresh", null);
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.text("code")).isEqualTo("INVALID_REFRESH_TOKEN");
    }

    @Test
    void businessRegistrationCreatesOrganizationAdmin() {
        Account admin = accounts().business("Installatori Srl");
        Response me = admin.api().get("/api/v1/me");
        assertThat(me.json().get("tenant").get("type").asString()).isEqualTo("BUSINESS");
        assertThat(me.json().get("tenant").get("name").asString()).isEqualTo("Installatori Srl");
        assertThat(me.json().get("roles").get(0).get("role").asString()).isEqualTo("ORGANIZATION_ADMIN");
        assertThat(me.json().get("roles").get(0).get("scopeType").asString()).isEqualTo("ORGANIZATION");
        assertThat(me.json().get("permissions").toString()).contains("role:manage").contains("audit:read");
    }

    @Test
    void businessRegistrationNeedsAnOrganizationName() {
        Response response = client().post("/api/v1/auth/register", Map.of("email", TestAccounts.uniqueEmail("org"),
                "password", TestAccounts.PASSWORD, "displayName", "Anna", "accountType", "BUSINESS"));
        assertThat(response.status()).isEqualTo(400);
        assertThat(response.text("code")).isEqualTo("ORGANIZATION_NAME_REQUIRED");
    }

    @Test
    void auditLogRecordsLoginAndLogout() {
        Account account = accounts().individual();
        account.client().post("/api/v1/auth/logout", null);
        Account again = accounts().login(client(), account.email(), account.password());

        Response audit = again.api().get("/api/v1/audit-logs");
        assertThat(audit.status()).isEqualTo(200);
        assertThat(audit.body()).contains("USER_REGISTERED").contains("EMAIL_VERIFIED").contains("LOGIN_SUCCESS")
                .contains("LOGOUT");
        assertThat(audit.body()).doesNotContain(TestAccounts.PASSWORD).doesNotContain("shsc_rt_");
    }
}
