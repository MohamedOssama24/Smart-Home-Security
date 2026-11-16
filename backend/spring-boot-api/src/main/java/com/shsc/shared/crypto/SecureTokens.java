package com.shsc.shared.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Opaque secrets: 256 random bits, base64url, with a readable prefix (helps secret scanners).
 * Only the SHA-256 hash of a secret is ever stored.
 */
public final class SecureTokens {

    public static final String REFRESH_TOKEN_PREFIX = "shsc_rt_";
    public static final String EMAIL_TOKEN_PREFIX = "shsc_et_";
    public static final String ENROLLMENT_TOKEN_PREFIX = "shsc_enr_";
    public static final String AGENT_ACCESS_TOKEN_PREFIX = "shsc_at_";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private SecureTokens() {
    }

    public static String generate(String prefix) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return prefix + ENCODER.encodeToString(bytes);
    }

    public static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static String sha256Hex(String value) {
        return HexFormat.of().formatHex(sha256(value));
    }
}
