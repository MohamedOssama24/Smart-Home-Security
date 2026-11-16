package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.shsc.identity.password.PasswordPolicy;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @Test
    void acceptsLongUncommonPasswords() {
        assertThat(policy.violations("Lungo-e-sicuro-42!", "mario@example.test", "Mario Rossi")).isEmpty();
        assertThat(policy.violations("correct horse battery staple", null, null)).isEmpty();
    }

    @Test
    void rejectsShortAndOverlyLongPasswords() {
        assertThat(policy.violations("Corta-1!", null, null)).containsExactly("PASSWORD_TOO_SHORT");
        assertThat(policy.violations("a".repeat(129), null, null)).containsExactly("PASSWORD_TOO_LONG");
        assertThat(policy.violations(null, null, null)).containsExactly("PASSWORD_TOO_SHORT");
    }

    @Test
    void rejectsCommonSimpleAndPersonalPasswords() {
        assertThat(policy.violations("Password1234", null, null)).contains("PASSWORD_TOO_COMMON");
        assertThat(policy.violations("zzzzzzzzzzzzzz", null, null)).contains("PASSWORD_TOO_SIMPLE");
        assertThat(policy.violations("987654321098765", null, null)).isEmpty();
        assertThat(policy.violations("123456789012", null, null)).contains("PASSWORD_TOO_COMMON");
        assertThat(policy.violations("mario.rossi-2026!", "mario.rossi@example.test", null))
                .contains("PASSWORD_CONTAINS_PERSONAL_DATA");
        assertThat(policy.violations("Ciao-Giuseppe-77", "x@example.test", "Giuseppe Verdi"))
                .contains("PASSWORD_CONTAINS_PERSONAL_DATA");
    }
}
