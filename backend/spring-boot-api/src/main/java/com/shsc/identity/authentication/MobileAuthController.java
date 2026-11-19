package com.shsc.identity.authentication;

import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.identity.authentication.AuthController.LoginRequest;
import com.shsc.identity.session.SessionService;
import com.shsc.identity.session.SessionService.IssuedSession;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Authentication of the mobile app (docs/06-SECURITY-AUTH-TENANCY.md, docs/23-MOBILE-APP.md §2):
 * the same accounts, sessions, rotation, reuse detection, lockout and audit as the web dashboard,
 * but the refresh token travels in the JSON body and is kept by the app in the platform keystore
 * ({@code flutter_secure_storage}). No cookie is read or set, so these endpoints need no CSRF
 * header (see SecurityConfig).
 */
@RestController
@RequestMapping("/api/v1/auth/mobile")
public class MobileAuthController {

    public record RefreshRequest(@NotBlank @Size(max = 200) String refreshToken) {
    }

    public record MobileTokenResponse(String accessToken, String tokenType, long expiresIn, Instant expiresAt,
            UUID sessionId, String refreshToken, Instant refreshExpiresAt) {
        static MobileTokenResponse of(IssuedSession s) {
            return new MobileTokenResponse(s.accessToken().value(), "Bearer", s.accessToken().ttl().toSeconds(),
                    s.accessToken().expiresAt(), s.sessionId(), s.refreshToken(), s.refreshExpiresAt());
        }
    }

    private final AuthenticationService authentication;
    private final SessionService sessions;

    public MobileAuthController(AuthenticationService authentication, SessionService sessions) {
        this.authentication = authentication;
        this.sessions = sessions;
    }

    @PostMapping("/login")
    public MobileTokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return MobileTokenResponse.of(authentication.login(request.email(), request.password(),
                request.deviceLabel(), ClientInfo.from(http)).session());
    }

    /** Rotation: the old refresh token is consumed; presenting it again revokes the session. */
    @PostMapping("/refresh")
    public MobileTokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest http) {
        return MobileTokenResponse.of(sessions.refresh(request.refreshToken(), ClientInfo.from(http)));
    }

    /** Revokes the session: its push registrations stop receiving notifications. */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshRequest request, HttpServletRequest http) {
        sessions.logout(request.refreshToken(), ClientInfo.from(http));
    }
}
