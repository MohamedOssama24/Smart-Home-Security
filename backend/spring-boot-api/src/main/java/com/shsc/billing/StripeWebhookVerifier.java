package com.shsc.billing;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies the {@code Stripe-Signature} header: {@code t=<unix>,v1=<hex>[,v1=...]} where v1 is
 * HMAC-SHA256(secret, t + "." + raw body). The timestamp must be within the tolerance (replay
 * protection) and at least one v1 must match (constant-time comparison). Other schemes are ignored.
 */
public final class StripeWebhookVerifier {

    public static final class InvalidSignatureException extends RuntimeException {
        InvalidSignatureException(String message) {
            super(message);
        }
    }

    private final byte[] secret;
    private final Duration tolerance;

    public StripeWebhookVerifier(String secret, Duration tolerance) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("webhook secret required");
        }
        this.secret = secret.strip().getBytes(StandardCharsets.UTF_8);
        this.tolerance = tolerance;
    }

    public void verify(String header, byte[] payload, Instant now) {
        if (header == null || header.length() > 2048) {
            throw new InvalidSignatureException("missing or oversized signature header");
        }
        Long timestamp = null;
        List<byte[]> signatures = new ArrayList<>();
        for (String part : header.split(",")) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = part.substring(0, eq).strip();
            String value = part.substring(eq + 1).strip();
            if ("t".equals(key) && value.matches("[0-9]{1,12}")) {
                timestamp = Long.parseLong(value);
            } else if ("v1".equals(key) && value.matches("[0-9a-fA-F]{64}")) {
                signatures.add(HexFormat.of().parseHex(value));
            }
        }
        if (timestamp == null || signatures.isEmpty()) {
            throw new InvalidSignatureException("malformed signature header");
        }
        long age = Math.abs(now.getEpochSecond() - timestamp);
        if (age > tolerance.toSeconds()) {
            throw new InvalidSignatureException("timestamp outside tolerance");
        }
        byte[] expected = sign(timestamp, payload);
        for (byte[] candidate : signatures) {
            if (MessageDigest.isEqual(expected, candidate)) {
                return;
            }
        }
        throw new InvalidSignatureException("no matching signature");
    }

    /** Header value as Stripe would send it (used by the tests). */
    public String header(long timestamp, byte[] payload) {
        return "t=" + timestamp + ",v1=" + HexFormat.of().formatHex(sign(timestamp, payload));
    }

    private byte[] sign(long timestamp, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.US_ASCII));
            return mac.doFinal(payload);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }
}
