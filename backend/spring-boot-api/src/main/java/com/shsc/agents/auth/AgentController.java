package com.shsc.agents.auth;

import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.agents.auth.AgentAuthService.Enrolled;
import com.shsc.agents.auth.AgentAuthService.EnrollmentRequest;
import com.shsc.agents.auth.AgentAuthService.IssuedAgentToken;
import com.shsc.homes.HomeRepository.Home;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Agent API (agent credentials only; user JWTs are not accepted on this path). */
@RestController
@RequestMapping("/api/v1/agent")
public class AgentController {

    public record EnrollRequest(
            @NotBlank @Size(max = 200) String enrollmentToken,
            @NotBlank @Size(max = 100) String publicKey,
            @Size(max = 100) String name,
            @Size(max = 255) String hostname,
            @NotBlank @Pattern(regexp = "windows|linux|darwin") String os,
            @NotBlank @Pattern(regexp = "[a-z0-9_]{1,16}") String arch,
            @NotBlank @Size(max = 64) @Pattern(regexp = "[0-9A-Za-z.+_-]+") String agentVersion) {
    }

    public record EnrollResponse(UUID agentId, UUID homeId, UUID credentialId) {
    }

    public record TokenRequest(@NotBlank @Size(max = 4096) String assertion) {
    }

    public record TokenResponse(String accessToken, String tokenType, long expiresIn, Instant expiresAt) {
    }

    public record RotateRequest(@NotBlank @Size(max = 100) String publicKey, @NotBlank @Size(max = 4096) String proof) {
    }

    public record RotateResponse(UUID credentialId) {
    }

    public record SessionResponse(UUID agentId, UUID homeId, String homeName, UUID credentialId,
            Instant tokenExpiresAt) {
    }

    private final AgentAuthService agentAuth;

    public AgentController(AgentAuthService agentAuth) {
        this.agentAuth = agentAuth;
    }

    @PostMapping("/enroll")
    @ResponseStatus(HttpStatus.CREATED)
    public EnrollResponse enroll(@Valid @RequestBody EnrollRequest request, HttpServletRequest http) {
        Enrolled enrolled = agentAuth.enroll(new EnrollmentRequest(request.enrollmentToken(), request.publicKey(),
                request.name(), request.hostname(), request.os(), request.arch(), request.agentVersion()),
                ClientInfo.from(http));
        return new EnrollResponse(enrolled.agentId(), enrolled.homeId(), enrolled.credentialId());
    }

    @PostMapping("/token")
    public TokenResponse token(@Valid @RequestBody TokenRequest request, HttpServletRequest http) {
        IssuedAgentToken token = agentAuth.issueToken(request.assertion(), ClientInfo.from(http));
        return new TokenResponse(token.accessToken(), "Bearer", token.ttl().toSeconds(), token.expiresAt());
    }

    /** Verifies the agent ↔ home association and returns the identity seen by the backend. */
    @GetMapping("/session")
    public SessionResponse session(@AuthenticationPrincipal AgentPrincipal agent) {
        Home home = agentAuth.requireHome(agent);
        return new SessionResponse(agent.agentId(), home.id(), home.name(), agent.credentialId(),
                agent.tokenExpiresAt());
    }

    @PostMapping("/credentials/rotate")
    public RotateResponse rotate(@AuthenticationPrincipal AgentPrincipal agent,
            @Valid @RequestBody RotateRequest request, HttpServletRequest http) {
        agentAuth.requireHome(agent);
        return new RotateResponse(agentAuth.rotate(agent, request.publicKey(), request.proof(), ClientInfo.from(http)));
    }
}
