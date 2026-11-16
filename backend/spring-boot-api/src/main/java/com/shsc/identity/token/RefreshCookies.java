package com.shsc.identity.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.shsc.shared.config.ShscProperties;

/**
 * Refresh token transport for the web dashboard: cookie {@code HttpOnly; Secure;
 * SameSite=Strict; Path=/api/v1/auth}. JavaScript never sees it, it is sent only to the auth
 * endpoints, and those endpoints additionally require the CSRF double-submit header.
 */
@Component
public class RefreshCookies {

    public static final String PATH = "/api/v1/auth";

    private final ShscProperties.Session settings;
    private final Clock clock;

    public RefreshCookies(ShscProperties properties, Clock clock) {
        this.settings = properties.security().session();
        this.clock = clock;
    }

    public String name() {
        return settings.cookieName();
    }

    public ResponseCookie issue(String token, Instant expiresAt) {
        Duration maxAge = Duration.between(clock.instant(), expiresAt);
        return base(token).maxAge(maxAge.isNegative() ? Duration.ZERO : maxAge).build();
    }

    public ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(settings.cookieName(), value)
                .httpOnly(true)
                .secure(settings.cookieSecure())
                .sameSite("Strict")
                .path(PATH);
    }
}
