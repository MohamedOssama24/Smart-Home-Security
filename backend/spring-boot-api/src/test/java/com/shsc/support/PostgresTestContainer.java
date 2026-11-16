package com.shsc.support;

import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

/**
 * PostgreSQL 18 started with the SAME init script used by docker-compose, so tests run
 * against the real role model (migrator + runtime role without BYPASSRLS). Also provides the
 * other required settings (JWT key generated per test run, never a fixed secret).
 */
public final class PostgresTestContainer {

    public static final String MIGRATOR_USER = "shsc_migrator_test";
    public static final String MIGRATOR_PASSWORD = "migrator-test-pw";
    public static final String APP_USER = "shsc_app_test";
    public static final String APP_PASSWORD = "app-test-pw";

    private static final Path INIT_SCRIPT =
            Path.of("..", "..", "infrastructure", "docker", "postgres", "init", "01-roles.sh");

    public static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine")
            .withDatabaseName("shsc")
            .withEnv("SHSC_DB_MIGRATOR_USER", MIGRATOR_USER)
            .withEnv("SHSC_DB_MIGRATOR_PASSWORD", MIGRATOR_PASSWORD)
            .withEnv("SHSC_DB_APP_USER", APP_USER)
            .withEnv("SHSC_DB_APP_PASSWORD", APP_PASSWORD)
            .withCopyFileToContainer(
                    MountableFile.forHostPath(INIT_SCRIPT.toAbsolutePath(), 0755),
                    "/docker-entrypoint-initdb.d/01-roles.sh");

    private static final String JWT_PRIVATE_KEY = generateEcKey();

    static {
        POSTGRES.start();
    }

    private PostgresTestContainer() {
    }

    public static void register(DynamicPropertyRegistry registry) {
        registry.add("SHSC_DB_URL", POSTGRES::getJdbcUrl);
        registry.add("SHSC_DB_APP_USER", () -> APP_USER);
        registry.add("SHSC_DB_APP_PASSWORD", () -> APP_PASSWORD);
        registry.add("SHSC_DB_MIGRATOR_USER", () -> MIGRATOR_USER);
        registry.add("SHSC_DB_MIGRATOR_PASSWORD", () -> MIGRATOR_PASSWORD);
        registry.add("SHSC_JWT_PRIVATE_KEY", () -> JWT_PRIVATE_KEY);
        registry.add("SHSC_PUBLIC_BASE_URL", () -> "https://shsc.test");
        registry.add("SHSC_MAIL_FROM", () -> "no-reply@shsc.test");
    }

    private static String generateEcKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }
}
