package com.shsc.billing;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import com.shsc.billing.StripeWebhookVerifier.InvalidSignatureException;

/** Stripe-Signature verification (MOCK secrets): tolerance, key rotation (several v1), tampering. */
class StripeWebhookVerifierTest {

    private static final byte[] BODY = "{\"id\":\"evt_MOCK\"}".getBytes(StandardCharsets.UTF_8);
    private final StripeWebhookVerifier verifier = new StripeWebhookVerifier("whsec_MOCK_a", Duration.ofMinutes(5));
    private final StripeWebhookVerifier other = new StripeWebhookVerifier("whsec_MOCK_b", Duration.ofMinutes(5));
    private final Instant now = Instant.parse("2026-11-18T12:00:00Z");

    @Test
    void acceptsAValidSignatureAmongOthers() {
        long t = now.getEpochSecond() - 10;
        String good = verifier.header(t, BODY);
        String rotated = other.header(t, BODY).replace("t=" + t + ",", "") + "," + good.substring(good.indexOf("v1="));
        assertThatCode(() -> verifier.verify(good, BODY, now)).doesNotThrowAnyException();
        assertThatCode(() -> verifier.verify("t=" + t + "," + rotated + ",v0=abc", BODY, now))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsWrongSecretTamperingReplayAndMalformedHeaders() {
        long t = now.getEpochSecond();
        assertThatThrownBy(() -> verifier.verify(other.header(t, BODY), BODY, now))
                .isInstanceOf(InvalidSignatureException.class);
        assertThatThrownBy(() -> verifier.verify(verifier.header(t, BODY), "{}".getBytes(StandardCharsets.UTF_8), now))
                .isInstanceOf(InvalidSignatureException.class);
        assertThatThrownBy(() -> verifier.verify(verifier.header(t - 301, BODY), BODY, now))
                .isInstanceOf(InvalidSignatureException.class);
        assertThatThrownBy(() -> verifier.verify(verifier.header(t + 301, BODY), BODY, now))
                .isInstanceOf(InvalidSignatureException.class);
        for (String header : new String[] { null, "", "t=abc,v1=00", "v1=" + "0".repeat(64), "t=" + t,
                "x".repeat(3000) }) {
            assertThatThrownBy(() -> verifier.verify(header, BODY, now)).isInstanceOf(InvalidSignatureException.class);
        }
    }
}
