package com.shsc.identity.password;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration(proxyBeanMethods = false)
class PasswordConfig {

    static final String ARGON2ID = "argon2id";

    /**
     * Argon2id with the OWASP baseline (m = 19 MiB, t = 2, p = 1, 16-byte salt, 32-byte hash).
     * Wrapped in a DelegatingPasswordEncoder ("{argon2id}..."), so parameters or algorithm can
     * evolve: stored hashes are upgraded transparently at the next successful login.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        Argon2PasswordEncoder argon2id = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
        return new DelegatingPasswordEncoder(ARGON2ID, Map.of(ARGON2ID, argon2id));
    }
}
