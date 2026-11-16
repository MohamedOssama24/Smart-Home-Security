package com.shsc.identity.authentication;

import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.identity.authentication.AuthenticationService.AccountType;
import com.shsc.identity.authentication.AuthenticationService.LoginResult;
import com.shsc.identity.authentication.AuthenticationService.Registration;
import com.shsc.identity.session.SessionService;
import com.shsc.identity.session.SessionService.IssuedSession;
import com.shsc.identity.token.RefreshCookies;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Public authentication endpoints. Every POST here requires the CSRF header
 * (double-submit cookie, see SecurityConfig) because refresh and logout rely on a cookie.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 1024) String password,
            @NotBlank @Size(max = 100) String displayName,
            @Pattern(regexp = "it|en") String locale,
            @NotNull AccountType accountType,
            @Size(max = 200) String organizationName) {
    }

    public record LoginRequest(
            @NotBlank @Size(max = 254) String email,
            @NotBlank @Size(max = 1024) String password,
            @Size(max = 100) String deviceLabel) {
    }

    public record EmailRequest(@NotBlank @Email @Size(max = 254) String email) {
    }

    public record TokenRequest(@NotBlank @Size(max = 200) String token) {
    }

    public record ResetPasswordRequest(@NotBlank @Size(max = 200) String token,
            @NotBlank @Size(max = 1024) String newPassword) {
    }

    public record TokenResponse(String accessToken, String tokenType, long expiresIn, Instant expiresAt,
            UUID sessionId) {
        static TokenResponse of(IssuedSession session) {
            return new TokenResponse(session.accessToken().value(), "Bearer",
                    session.accessToken().ttl().toSeconds(), session.accessToken().expiresAt(), session.sessionId());
        }
    }

    private final AuthenticationService authentication;
    private final SessionService sessions;
    private final RefreshCookies cookies;

    public AuthController(AuthenticationService authentication, SessionService sessions, RefreshCookies cookies) {
        this.authentication = authentication;
        this.sessions = sessions;
        this.cookies = cookies;
    }

    /** Issues the XSRF-TOKEN cookie read by the SPA (Angular sends it back as X-XSRF-TOKEN). */
    @GetMapping("/csrf")
    public ResponseEntity<Void> csrf(CsrfToken token) {
        token.getToken();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        authentication.register(new Registration(request.email(), request.password(), request.displayName(),
                request.locale(), request.accountType(), request.organizationName()), ClientInfo.from(http));
    }

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verifyEmail(@Valid @RequestBody TokenRequest request, HttpServletRequest http) {
        authentication.verifyEmail(request.token(), ClientInfo.from(http));
    }

    @PostMapping("/verify-email/resend")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void resendVerification(@Valid @RequestBody EmailRequest request, HttpServletRequest http) {
        authentication.resendVerification(request.email(), ClientInfo.from(http));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        LoginResult result = authentication.login(request.email(), request.password(), request.deviceLabel(),
                ClientInfo.from(http));
        return withRefreshCookie(result.session());
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest http) {
        IssuedSession session = sessions.refresh(readCookie(http), ClientInfo.from(http));
        return withRefreshCookie(session);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest http) {
        sessions.logout(readCookie(http), ClientInfo.from(http));
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookies.clear().toString()).build();
    }

    @PostMapping("/password/forgot")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void forgotPassword(@Valid @RequestBody EmailRequest request, HttpServletRequest http) {
        authentication.forgotPassword(request.email(), ClientInfo.from(http));
    }

    @PostMapping("/password/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request, HttpServletRequest http) {
        authentication.resetPassword(request.token(), request.newPassword(), ClientInfo.from(http));
    }

    /** The invited user chooses the password (link received by e-mail). */
    @PostMapping("/invitation/accept")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void acceptInvitation(@Valid @RequestBody ResetPasswordRequest request, HttpServletRequest http) {
        authentication.acceptInvitation(request.token(), request.newPassword(), ClientInfo.from(http));
    }

    private ResponseEntity<TokenResponse> withRefreshCookie(IssuedSession session) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookies.issue(session.refreshToken(), session.refreshExpiresAt()).toString())
                .body(TokenResponse.of(session));
    }

    private String readCookie(HttpServletRequest http) {
        if (http.getCookies() == null) {
            return null;
        }
        for (var cookie : http.getCookies()) {
            if (cookies.name().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
