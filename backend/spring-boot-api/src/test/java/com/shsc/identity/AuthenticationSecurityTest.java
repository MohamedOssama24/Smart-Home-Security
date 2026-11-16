package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.support.ApiClient;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.IntegrationTest;
import com.shsc.support.Mailbox;
import com.shsc.support.TestAccounts;
import com.shsc.support.TestAccounts.Account;

/** Brute force, enumeration, CSRF, password policy, reset and change of password. */
class AuthenticationSecurityTest extends IntegrationTest {

    @Test
    void wrongPasswordAndUnknownEmailGiveTheSameAnswer() {
        Account account = accounts().individual();

        Response wrongPassword = client().post("/api/v1/auth/login",
                Map.of("email", account.email(), "password", "Sbagliata-ma-lunga-1"));
        Response unknown = client().post("/api/v1/auth/login",
                Map.of("email", TestAccounts.uniqueEmail("nobody"), "password", "Sbagliata-ma-lunga-1"));

        assertThat(wrongPassword.status()).isEqualTo(401);
        assertThat(unknown.status()).isEqualTo(401);
        assertThat(wrongPassword.text("code")).isEqualTo("INVALID_CREDENTIALS");
        assertThat(unknown.text("code")).isEqualTo("INVALID_CREDENTIALS");
        assertThat(wrongPassword.text("detail")).isEqualTo(unknown.text("detail"));
    }

    @Test
    void registeringAnExistingEmailLooksLikeANewRegistration() {
        Account account = accounts().individual();
        Map<String, Object> again = Map.of("email", account.email(), "password", "Altra-password-lunga-9",
                "displayName", "Intruso", "accountType", "INDIVIDUAL");

        Response response = client().post("/api/v1/auth/register", again);
        Response fresh = client().post("/api/v1/auth/register", Map.of("email", TestAccounts.uniqueEmail("new"),
                "password", "Altra-password-lunga-9", "displayName", "Nuovo", "accountType", "INDIVIDUAL"));

        assertThat(response.status()).isEqualTo(202);
        assertThat(response.body()).isEqualTo(fresh.body());
        // the owner is informed by e-mail instead
        assertThat(mailbox().await(account.email(), 2).getSubject()).contains("Tentativo di registrazione");
    }

    @Test
    void forgotPasswordAnswersTheSameForUnknownEmails() {
        Response unknown = client().post("/api/v1/auth/password/forgot",
                Map.of("email", TestAccounts.uniqueEmail("ghost")));
        assertThat(unknown.status()).isEqualTo(202);
    }

    @Test
    void repeatedFailuresLockTheAccountTemporarily() {
        Account account = accounts().individual();
        Map<String, Object> wrong = Map.of("email", account.email(), "password", "Sbagliata-ma-lunga-1");
        for (int i = 0; i < 5; i++) {
            // different IPs: the lock follows the account, not only the address
            assertThat(client().post("/api/v1/auth/login", wrong).status()).isEqualTo(401);
        }
        Response locked = client().post("/api/v1/auth/login",
                Map.of("email", account.email(), "password", account.password()));
        assertThat(locked.status()).isEqualTo(429);
        assertThat(locked.text("code")).isEqualTo("TOO_MANY_ATTEMPTS");
        assertThat(locked.header("Retry-After")).isPresent();
    }

    @Test
    void unknownEmailsAreThrottledLikeExistingOnes() {
        String ghost = TestAccounts.uniqueEmail("ghost");
        Map<String, Object> attempt = Map.of("email", ghost, "password", "Qualcosa-di-lungo-1"); // gitleaks:allow (fake test password)
        for (int i = 0; i < 5; i++) {
            assertThat(client().post("/api/v1/auth/login", attempt).status()).isEqualTo(401);
        }
        assertThat(client().post("/api/v1/auth/login", attempt).status()).isEqualTo(429);
    }

    @Test
    void oneIpCannotTryManyAccounts() {
        ApiClient attacker = client();
        int status = 0;
        for (int i = 0; i < 31; i++) {
            status = attacker.post("/api/v1/auth/login",
                    Map.of("email", TestAccounts.uniqueEmail("spray"), "password", "Password-spray-123")).status();
        }
        assertThat(status).isEqualTo(429);
    }

    @Test
    void authPostsWithoutCsrfTokenAreRejected() {
        ApiClient noCsrf = client().withoutCsrf();
        Response response = noCsrf.post("/api/v1/auth/login", Map.of("email", "a@b.test", "password", "x"));
        assertThat(response.status()).isEqualTo(403);
        assertThat(response.text("code")).isEqualTo("CSRF_INVALID");

        // cookie present but the header does not match it (double-submit check)
        ApiClient forged = client().withoutCsrf();
        forged.get("/api/v1/auth/csrf");
        assertThat(forged.cookie("XSRF-TOKEN")).isNotBlank();
        Response mismatch = forged.send("POST", "/api/v1/auth/refresh", null, Map.of("X-XSRF-TOKEN", "forged"));
        assertThat(mismatch.status()).isEqualTo(403);
    }

    @Test
    void csrfCookieIsReadableButStrict() {
        Response csrf = client().get("/api/v1/auth/csrf");
        assertThat(csrf.status()).isEqualTo(204);
        String cookie = csrf.setCookie("XSRF-TOKEN").orElseThrow();
        assertThat(cookie).doesNotContain("HttpOnly").contains("SameSite=Strict").contains("Secure");
    }

    @Test
    void bearerRequestsDoNotClearTheCsrfCookie() {
        Account account = accounts().individual();
        ApiClient api = account.api();
        String csrf = api.cookie("XSRF-TOKEN");
        assertThat(csrf).isNotBlank();

        Response homes = api.get("/api/v1/homes");
        assertThat(homes.status()).isEqualTo(200);
        assertThat(homes.setCookie("XSRF-TOKEN")).isEmpty();
        Response created = api.post("/api/v1/homes", Map.of("name", "Casa"));
        assertThat(created.status()).isEqualTo(201);
        assertThat(created.setCookie("XSRF-TOKEN")).isEmpty();

        // the browser still holds the same token, so refresh works without fetching a new one
        assertThat(api.cookie("XSRF-TOKEN")).isEqualTo(csrf);
        assertThat(api.post("/api/v1/auth/refresh", null).status()).isEqualTo(200);
    }

    @Test
    void passwordPolicyIsEnforced() {
        String email = TestAccounts.uniqueEmail("policy");
        for (String[] c : new String[][] {
            {"corta1!", "PASSWORD_TOO_SHORT"},
            {"password1234", "PASSWORD_TOO_COMMON"},
            {"aaaaaaaaaaaaaaa", "PASSWORD_TOO_SIMPLE"},
            {"abcdefghijklmnop", "PASSWORD_TOO_SIMPLE"},
            {email.substring(0, email.indexOf('@')) + "-2026", "PASSWORD_CONTAINS_PERSONAL_DATA"}}) {
            Response response = client().post("/api/v1/auth/register", Map.of("email", email, "password", c[0],
                    "displayName", "Policy", "accountType", "INDIVIDUAL"));
            assertThat(response.status()).as(c[0]).isEqualTo(400);
            assertThat(response.text("code")).isEqualTo("PASSWORD_POLICY");
            assertThat(response.json().get("violations").toString()).as(c[0]).contains(c[1]);
        }
    }

    @Test
    void validationErrorsNeverEchoThePassword() {
        Response response = client().post("/api/v1/auth/register", Map.of("email", "not-an-email",
                "password", "Segreto-da-non-mostrare-1", "displayName", "X", "accountType", "INDIVIDUAL")); // gitleaks:allow (fake test password)
        assertThat(response.status()).isEqualTo(400);
        assertThat(response.text("code")).isEqualTo("VALIDATION_FAILED");
        assertThat(response.body()).doesNotContain("Segreto-da-non-mostrare-1");
    }

    @Test
    void passwordResetChangesThePasswordAndRevokesSessions() {
        Account account = accounts().individual();
        ApiClient anonymous = client();
        assertThat(anonymous.post("/api/v1/auth/password/forgot", Map.of("email", account.email())).status())
                .isEqualTo(202);
        String token = Mailbox.token(mailbox().await(account.email(), 2)).orElseThrow();
        assertThat(mailbox().await(account.email(), 2).getText()).contains("/reset-password#token=");

        Response weak = anonymous.post("/api/v1/auth/password/reset", Map.of("token", token, "newPassword", "corta"));
        assertThat(weak.text("code")).isEqualTo("PASSWORD_POLICY");

        String newPassword = "Nuova-password-sicura-7";
        assertThat(anonymous.post("/api/v1/auth/password/reset", Map.of("token", token, "newPassword", newPassword))
                .status()).isEqualTo(204);
        // token is single use
        assertThat(anonymous.post("/api/v1/auth/password/reset", Map.of("token", token, "newPassword", newPassword))
                .text("code")).isEqualTo("INVALID_TOKEN");
        // existing sessions are revoked
        assertThat(account.api().get("/api/v1/me").status()).isEqualTo(401);
        assertThat(client().post("/api/v1/auth/login", Map.of("email", account.email(), "password", account.password()))
                .status()).isEqualTo(401);
        accounts().login(client(), account.email(), newPassword);
    }

    @Test
    void passwordChangeNeedsCurrentPasswordAndRevokesOtherSessions() {
        Account account = accounts().individual();
        Account otherDevice = accounts().login(client(), account.email(), account.password());

        Response wrong = account.api().post("/api/v1/me/password",
                Map.of("currentPassword", "Non-e-questa-123", "newPassword", "Cambiata-davvero-55")); // gitleaks:allow (fake test password)
        assertThat(wrong.status()).isEqualTo(400);
        assertThat(wrong.text("code")).isEqualTo("INVALID_CURRENT_PASSWORD");

        Response changed = account.api().post("/api/v1/me/password",
                Map.of("currentPassword", account.password(), "newPassword", "Cambiata-davvero-55")); // gitleaks:allow (fake test password)
        assertThat(changed.status()).isEqualTo(204);
        assertThat(account.api().get("/api/v1/me").status()).isEqualTo(200);
        assertThat(otherDevice.api().get("/api/v1/me").status()).isEqualTo(401);
    }

    @Test
    void sessionsArePerDeviceAndCanBeRevoked() {
        Account first = accounts().individual();
        Account second = accounts().login(client(), first.email(), first.password());
        Account third = accounts().login(client(), first.email(), first.password());

        Response sessions = first.api().get("/api/v1/me/sessions");
        assertThat(sessions.json().size()).isEqualTo(3);
        String secondId = second.api().get("/api/v1/me").text("sessionId");

        assertThat(first.api().delete("/api/v1/me/sessions/" + secondId).status()).isEqualTo(204);
        assertThat(second.api().get("/api/v1/me").status()).isEqualTo(401);
        assertThat(third.api().get("/api/v1/me").status()).isEqualTo(200);

        Response all = first.api().post("/api/v1/me/sessions/revoke-all", Map.of("includeCurrent", true));
        assertThat(all.json().get("revoked").asInt()).isEqualTo(2);
        assertThat(first.api().get("/api/v1/me").status()).isEqualTo(401);
        assertThat(third.api().get("/api/v1/me").status()).isEqualTo(401);
    }

    @Test
    void someoneElsesSessionCannotBeRevoked() {
        Account alice = accounts().individual();
        Account bob = accounts().individual();
        String bobSession = bob.api().get("/api/v1/me").text("sessionId");

        assertThat(alice.api().delete("/api/v1/me/sessions/" + bobSession).status()).isEqualTo(404);
        assertThat(bob.api().get("/api/v1/me").status()).isEqualTo(200);
    }

    @Test
    void tamperedOrForeignTokensAreRejected() {
        Account account = accounts().individual();
        String token = account.accessToken();
        String tampered = token.substring(0, token.length() - 4) + (token.endsWith("AAAA") ? "BBBB" : "AAAA");
        assertThat(client().bearer(tampered).get("/api/v1/me").status()).isEqualTo(401);
        // "alg":"none" token
        String none = "eyJhbGciOiJub25lIn0." + token.split("\\.")[1] + ".";
        assertThat(client().bearer(none).get("/api/v1/me").status()).isEqualTo(401);
        assertThat(client().get("/api/v1/me").status()).isEqualTo(401);
    }
}
