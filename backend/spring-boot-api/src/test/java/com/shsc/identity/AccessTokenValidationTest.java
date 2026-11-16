package com.shsc.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.shsc.identity.token.JwtKeys;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;

/**
 * Tokens signed with the REAL server key but with one wrong claim must be rejected: this
 * proves every validator (expiry, issuer, audience, token_use, tid/sid, session binding)
 * is active, not only the signature check.
 */
class AccessTokenValidationTest extends IntegrationTest {

    @Autowired
    JwtKeys keys;

    private String sign(ECKey key, Account account, String sessionId, Consumer<JWTClaimsSet.Builder> change) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer("shsc-api")
                .audience("shsc-web")
                .subject(account.userId().toString())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .jwtID(UUID.randomUUID().toString())
                .claim("tid", account.tenantId().toString())
                .claim("sid", sessionId)
                .claim("roles", List.of("CUSTOMER"))
                .claim("token_use", "access");
        change.accept(claims);
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(),
                    claims.build());
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private int status(String token) {
        return client().bearer(token).get("/api/v1/me").status();
    }

    @Test
    void onlyTokensWithEveryClaimRightAreAccepted() throws JOSEException {
        Account account = accounts().individual();
        String session = account.api().get("/api/v1/me").text("sessionId");
        ECKey server = keys.jwk();
        Instant past = Instant.now().minusSeconds(3600);

        // control: a well-formed token built here is accepted, so the rejections below are
        // caused by the single wrong claim, not by the test harness
        assertThat(status(sign(server, account, session, c -> { }))).isEqualTo(200);

        assertThat(status(sign(server, account, session, c -> c.expirationTime(Date.from(past))))).isEqualTo(401);
        assertThat(status(sign(server, account, session, c -> c.issuer("someone-else")))).isEqualTo(401);
        assertThat(status(sign(server, account, session, c -> c.audience("shsc-agent-token")))).isEqualTo(401);
        assertThat(status(sign(server, account, session, c -> c.claim("token_use", "refresh")))).isEqualTo(401);
        assertThat(status(sign(server, account, session, c -> c.claim("sid", null)))).isEqualTo(401);
        assertThat(status(sign(server, account, session, c -> c.claim("tid", null)))).isEqualTo(401);
        // valid signature and claims, but for a session that does not exist
        assertThat(status(sign(server, account, UUID.randomUUID().toString(), c -> { }))).isEqualTo(401);
        // claims of another tenant with a real session: the session lookup is tenant-scoped
        assertThat(status(sign(server, account, session, c -> c.claim("tid", UUID.randomUUID().toString()))))
                .isEqualTo(401);

        // same claims signed by a different P-256 key
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID(server.getKeyID()).generate();
        assertThat(status(sign(attacker, account, session, c -> { }))).isEqualTo(401);
    }
}
