package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.support.ApiClient;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.Mailbox;
import com.shsc.support.TestAccounts;
import com.shsc.support.TestAccounts.Account;

/**
 * User management (Milestone 4): invitation with a one-time link, the invited user choosing
 * the password, enable / disable with immediate effect, guards (self, last administrator,
 * escalation, plan limit) and tenant isolation.
 */
class UserManagementTest extends IntegrationTest {

    @Autowired
    Fixtures fixtures;

    @Test
    void invitedUserChoosesPasswordAndGetsTheGrantedRole() {
        Account admin = accounts().business("Invito Srl");
        String homeId = Fixtures.createHome(admin, "Casa Rossi");
        String email = TestAccounts.uniqueEmail("invitato");

        Response invited = admin.api().post("/api/v1/users", invitation(email, "TECHNICIAN", "HOME", homeId));
        assertThat(invited.status()).as(invited.body()).isEqualTo(201);
        assertThat(invited.text("status")).isEqualTo("PENDING_VERIFICATION");
        assertThat(invited.json().get("invitationPending").asBoolean()).isTrue();
        assertThat(invited.json().get("roles").get(0).get("role").asString()).isEqualTo("TECHNICIAN");

        SimpleMailMessage mail = mailbox().await(email, 1);
        assertThat(mail.getSubject()).contains("Invito Srl");
        assertThat(mail.getText()).contains("/accept-invitation#token=").contains("Test User");
        String token = Mailbox.token(mail).orElseThrow();

        // without a password nobody can sign in, not even with an empty one
        ApiClient guest = client();
        assertThat(guest.post("/api/v1/auth/login", Map.of("email", email, "password", "qualsiasi-password-1"))
                .status()).isEqualTo(401);

        // the password policy applies
        Response weak = guest.post("/api/v1/auth/invitation/accept", Map.of("token", token, "newPassword", "corta"));
        assertThat(weak.status()).isEqualTo(400);
        assertThat(weak.text("code")).isEqualTo("PASSWORD_POLICY");

        assertThat(guest.post("/api/v1/auth/invitation/accept",
                Map.of("token", token, "newPassword", TestAccounts.PASSWORD)).status()).isEqualTo(204);
        // single use
        Response reused = guest.post("/api/v1/auth/invitation/accept",
                Map.of("token", token, "newPassword", "Un-altra-password-99"));
        assertThat(reused.status()).isEqualTo(400);
        assertThat(reused.text("code")).isEqualTo("INVALID_TOKEN");

        Account technician = accounts().login(client(), email, TestAccounts.PASSWORD);
        assertThat(technician.api().get("/api/v1/homes").json().size()).isEqualTo(1);
        assertThat(technician.api().get("/api/v1/me").json().get("roles").get(0).get("scopeType").asString())
                .isEqualTo("HOME");

        Response listed = admin.api().get("/api/v1/users/" + invited.text("id"));
        assertThat(listed.text("status")).isEqualTo("ACTIVE");
        assertThat(listed.json().get("invitationPending").asBoolean()).isFalse();
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("USER_INVITED").contains("INVITATION_ACCEPTED");
    }

    @Test
    void invitationCannotEscalateOrTargetExistingAccounts() {
        Account admin = accounts().business("Escalation Srl");
        Account technician = fixtures.addUser(accounts(), client(), admin, "TECHNICIAN", ScopeType.TENANT, null);
        Account stranger = accounts().individual();

        // only user:manage holders can invite
        assertThat(technician.api().post("/api/v1/users",
                invitation(TestAccounts.uniqueEmail("x"), "READ_ONLY", "TENANT", null)).status()).isEqualTo(403);
        // platform roles are never granted, and nothing is created when the role is refused
        String email = TestAccounts.uniqueEmail("super");
        assertThat(admin.api().post("/api/v1/users", invitation(email, "SUPER_ADMIN", "PLATFORM", null)).status())
                .isEqualTo(403);
        assertThat(admin.api().get("/api/v1/users").body()).doesNotContain(email);
        // an e-mail that already has an account (in any tenant) cannot be invited
        Response existing = admin.api().post("/api/v1/users", invitation(stranger.email(), "READ_ONLY", "TENANT", null));
        assertThat(existing.status()).isEqualTo(409);
        assertThat(existing.text("code")).isEqualTo("EMAIL_ALREADY_REGISTERED");
        assertThat(mailbox().messagesTo(stranger.email())).hasSize(1); // only the original verification e-mail
    }

    @Test
    void disablingRevokesSessionsAtOnceAndEnablingRestoresAccess() {
        Account admin = accounts().business("Disabilita Srl");
        Account user = fixtures.addUser(accounts(), client(), admin, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(user.api().get("/api/v1/homes").status()).isEqualTo(200);

        Response disabled = admin.api().patch("/api/v1/users/" + user.userId(), Map.of("status", "DISABLED"));
        assertThat(disabled.status()).as(disabled.body()).isEqualTo(200);
        assertThat(disabled.text("status")).isEqualTo("DISABLED");
        // same (still unexpired) access token: refused immediately
        assertThat(user.api().get("/api/v1/homes").status()).isEqualTo(401);
        assertThat(client().post("/api/v1/auth/login", Map.of("email", user.email(), "password",
                TestAccounts.PASSWORD)).status()).isEqualTo(401);

        assertThat(admin.api().patch("/api/v1/users/" + user.userId(), Map.of("status", "ACTIVE")).text("status"))
                .isEqualTo("ACTIVE");
        Account again = accounts().login(client(), user.email(), TestAccounts.PASSWORD);
        // roles were kept
        assertThat(again.api().get("/api/v1/homes").status()).isEqualTo(200);
        assertThat(admin.api().get("/api/v1/audit-logs").body()).contains("USER_DISABLED").contains("USER_ENABLED");
    }

    @Test
    void administratorCannotDisableThemselvesNorTheLastAdministrator() {
        Account admin = accounts().business("Ultimo Admin Srl");
        Response self = admin.api().patch("/api/v1/users/" + admin.userId(), Map.of("status", "DISABLED"));
        assertThat(self.status()).isEqualTo(409);
        assertThat(self.text("code")).isEqualTo("CANNOT_DISABLE_SELF");

        Account second = fixtures.addUser(accounts(), client(), admin, "ORGANIZATION_ADMIN", ScopeType.TENANT, null);
        // two administrators: one can disable the other ...
        assertThat(second.api().patch("/api/v1/users/" + admin.userId(), Map.of("status", "DISABLED")).status())
                .isEqualTo(200);
        // ... and the remaining one is the last: a disabled admin does not count
        String assignment = second.api().get("/api/v1/users/" + second.userId() + "/roles").json().get(0)
                .get("id").asString();
        Response last = second.api().delete("/api/v1/users/" + second.userId() + "/roles/" + assignment);
        assertThat(last.status()).isEqualTo(409);
        assertThat(last.text("code")).isEqualTo("LAST_ADMIN");
    }

    @Test
    void displayNameCanBeChangedAndInvitationResent() {
        Account admin = accounts().business("Rinvio Srl");
        String email = TestAccounts.uniqueEmail("rinvio");
        String id = admin.api().post("/api/v1/users", invitation(email, "READ_ONLY", "TENANT", null)).text("id");
        String first = Mailbox.token(mailbox().await(email, 1)).orElseThrow();

        assertThat(admin.api().post("/api/v1/users/" + id + "/invitation", null).status()).isEqualTo(202);
        String second = Mailbox.token(mailbox().await(email, 2)).orElseThrow();
        // the previous link stops working
        assertThat(client().post("/api/v1/auth/invitation/accept",
                Map.of("token", first, "newPassword", TestAccounts.PASSWORD)).status()).isEqualTo(400);
        assertThat(client().post("/api/v1/auth/invitation/accept",
                Map.of("token", second, "newPassword", TestAccounts.PASSWORD)).status()).isEqualTo(204);
        Response resend = admin.api().post("/api/v1/users/" + id + "/invitation", null);
        assertThat(resend.status()).isEqualTo(409);
        assertThat(resend.text("code")).isEqualTo("INVITATION_NOT_PENDING");

        assertThat(admin.api().patch("/api/v1/users/" + id, Map.of("displayName", "Nome Nuovo")).text("displayName"))
                .isEqualTo("Nome Nuovo");
    }

    @Test
    void invitationsRespectTheFreePlanUserLimit() {
        Account admin = accounts().business("Limite Utenti Srl");
        // FREE: 3 users, the administrator is the first
        for (int i = 0; i < 2; i++) {
            assertThat(admin.api().post("/api/v1/users",
                    invitation(TestAccounts.uniqueEmail("u" + i), "READ_ONLY", "TENANT", null)).status()).isEqualTo(201);
        }
        Response over = admin.api().post("/api/v1/users",
                invitation(TestAccounts.uniqueEmail("troppi"), "READ_ONLY", "TENANT", null));
        assertThat(over.status()).isEqualTo(409);
        assertThat(over.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
        assertThat(over.text("resource")).isEqualTo("USERS");

        // a disabled user frees a seat; re-enabling it is then refused while the plan is full
        String someone = admin.api().get("/api/v1/users").json().get(1).get("id").asString();
        admin.api().patch("/api/v1/users/" + someone, Map.of("status", "DISABLED"));
        assertThat(admin.api().post("/api/v1/users",
                invitation(TestAccounts.uniqueEmail("posto"), "READ_ONLY", "TENANT", null)).status()).isEqualTo(201);
        Response reenable = admin.api().patch("/api/v1/users/" + someone, Map.of("status", "ACTIVE"));
        assertThat(reenable.status()).isEqualTo(409);
        assertThat(reenable.text("code")).isEqualTo("PLAN_LIMIT_REACHED");
    }

    @Test
    void usersOfAnotherTenantAreInvisible() {
        Account alice = accounts().business("Alfa Srl");
        Account bob = accounts().business("Beta Srl");
        assertThat(bob.api().get("/api/v1/users/" + alice.userId()).status()).isEqualTo(404);
        assertThat(bob.api().patch("/api/v1/users/" + alice.userId(), Map.of("status", "DISABLED")).status())
                .isEqualTo(404);
        assertThat(bob.api().post("/api/v1/users/" + alice.userId() + "/invitation", null).status()).isEqualTo(404);
        assertThat(bob.api().get("/api/v1/users").body()).doesNotContain(alice.email());
    }

    private static Map<String, Object> invitation(String email, String role, String scopeType, String scopeId) {
        Map<String, Object> body = new HashMap<>(Map.of("email", email, "displayName", "Test User", "locale", "it",
                "role", role, "scopeType", scopeType));
        if (scopeId != null) {
            body.put("scopeId", scopeId);
        }
        return body;
    }
}
