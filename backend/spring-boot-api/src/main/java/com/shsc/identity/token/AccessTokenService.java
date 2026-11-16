package com.shsc.identity.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.shsc.shared.config.ShscProperties;

/**
 * Issues short-lived ES256 access tokens for users. Claims: sub (user), tid (tenant),
 * sid (session), roles (informational for the UI; authorization always re-reads the DB).
 */
@Service
public class AccessTokenService {

    public record IssuedAccessToken(String value, Instant expiresAt, Duration ttl) {
    }

    private final JwtEncoder encoder;
    private final JwtKeys keys;
    private final ShscProperties.Jwt settings;
    private final Clock clock;

    public AccessTokenService(JwtEncoder encoder, JwtKeys keys, ShscProperties properties, Clock clock) {
        this.encoder = encoder;
        this.keys = keys;
        this.settings = properties.security().jwt();
        this.clock = clock;
    }

    public IssuedAccessToken issue(UUID userId, UUID tenantId, UUID sessionId, List<String> roles) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(settings.accessTokenTtl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(settings.issuer())
                .audience(List.of(settings.audience()))
                .subject(userId.toString())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("tid", tenantId.toString())
                .claim("sid", sessionId.toString())
                .claim("roles", roles)
                .claim(JwtConfig.TOKEN_USE_CLAIM, JwtConfig.TOKEN_USE_ACCESS)
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.ES256).keyId(keys.keyId()).type("JWT").build();
        String value = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedAccessToken(value, expiresAt, settings.accessTokenTtl());
    }
}
