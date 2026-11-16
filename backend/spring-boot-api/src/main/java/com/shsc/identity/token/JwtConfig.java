package com.shsc.identity.token;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.shsc.shared.config.ShscProperties;

@Configuration(proxyBeanMethods = false)
class JwtConfig {

    static final String TOKEN_USE_CLAIM = "token_use";
    static final String TOKEN_USE_ACCESS = "access";

    @Bean
    JwtKeys jwtKeys(ShscProperties properties) {
        return JwtKeys.fromBase64Pkcs8(properties.security().jwt().privateKey());
    }

    @Bean
    JwtEncoder jwtEncoder(JwtKeys keys) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(keys.jwk())));
    }

    /** Only ES256 tokens issued by this API, for the web audience, of type "access". */
    @Bean
    JwtDecoder jwtDecoder(JwtKeys keys, ShscProperties properties) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256,
                new ImmutableJWKSet<>(new JWKSet(keys.jwk().toPublicJWK()))));
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        String audience = properties.security().jwt().audience();
        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> check(jwt.getAudience() != null
                && jwt.getAudience().contains(audience), "invalid audience");
        OAuth2TokenValidator<Jwt> typeValidator = jwt -> check(
                TOKEN_USE_ACCESS.equals(jwt.getClaimAsString(TOKEN_USE_CLAIM))
                        && jwt.getClaimAsString("tid") != null && jwt.getClaimAsString("sid") != null,
                "not an access token");
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(
                JwtValidators.createDefaultWithIssuer(properties.security().jwt().issuer()),
                audienceValidator, typeValidator)));
        return decoder;
    }

    private static OAuth2TokenValidatorResult check(boolean valid, String description) {
        return valid ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", description, null));
    }
}
