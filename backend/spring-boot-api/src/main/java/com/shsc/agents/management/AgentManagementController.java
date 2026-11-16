package com.shsc.agents.management;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.agents.management.AgentManagementService.CreatedEnrollmentToken;
import com.shsc.agents.management.AgentRepository.Agent;
import com.shsc.agents.management.AgentRepository.EnrollmentToken;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

/** Agent administration for users (user JWT). Agents themselves use /api/v1/agent/**. */
@RestController
public class AgentManagementController {

    public record EnrollmentTokenResponse(UUID id, UUID homeId, String state, Instant createdAt, Instant expiresAt,
            Instant usedAt, UUID usedByAgentId) {
        static EnrollmentTokenResponse of(EnrollmentToken t, Instant now) {
            return new EnrollmentTokenResponse(t.id(), t.homeId(), t.state(now), t.createdAt(), t.expiresAt(),
                    t.usedAt(), t.usedByAgentId());
        }
    }

    /** Returned once: the clear token is never stored nor shown again. */
    public record CreatedEnrollmentTokenResponse(UUID id, UUID homeId, String token, Instant expiresAt) {
    }

    public record AgentResponse(UUID id, UUID homeId, String name, String hostname, String os, String arch,
            String agentVersion, String status, Instant enrolledAt, Instant lastSeenAt, Instant revokedAt,
            String revokeReason) {
        static AgentResponse of(Agent a) {
            return new AgentResponse(a.id(), a.homeId(), a.name(), a.hostname(), a.os(), a.arch(), a.agentVersion(),
                    a.status().name(), a.enrolledAt(), a.lastSeenAt(), a.revokedAt(), a.revokeReason());
        }
    }

    public record RevokeAgentRequest(@Size(max = 200) String reason) {
    }

    private final AgentManagementService service;
    private final Clock clock;

    public AgentManagementController(AgentManagementService service, Clock clock) {
        this.service = service;
        this.clock = clock;
    }

    @PostMapping("/api/v1/homes/{homeId}/agent-enrollment-tokens")
    @ResponseStatus(HttpStatus.CREATED)
    public CreatedEnrollmentTokenResponse createToken(@PathVariable UUID homeId, HttpServletRequest http) {
        CreatedEnrollmentToken created = service.createEnrollmentToken(homeId, ClientInfo.from(http));
        return new CreatedEnrollmentTokenResponse(created.token().id(), homeId, created.secret(),
                created.token().expiresAt());
    }

    @GetMapping("/api/v1/homes/{homeId}/agent-enrollment-tokens")
    public List<EnrollmentTokenResponse> tokens(@PathVariable UUID homeId) {
        Instant now = clock.instant();
        return service.enrollmentTokens(homeId).stream().map(t -> EnrollmentTokenResponse.of(t, now)).toList();
    }

    @DeleteMapping("/api/v1/agent-enrollment-tokens/{tokenId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revokeToken(@PathVariable UUID tokenId, HttpServletRequest http) {
        service.revokeEnrollmentToken(tokenId, ClientInfo.from(http));
    }

    @GetMapping("/api/v1/homes/{homeId}/agents")
    public List<AgentResponse> agents(@PathVariable UUID homeId) {
        return service.agentsOfHome(homeId).stream().map(AgentResponse::of).toList();
    }

    @GetMapping("/api/v1/agents/{agentId}")
    public AgentResponse agent(@PathVariable UUID agentId) {
        return AgentResponse.of(service.agent(agentId));
    }

    @PostMapping("/api/v1/agents/{agentId}/revoke")
    public AgentResponse revoke(@PathVariable UUID agentId,
            @Valid @RequestBody(required = false) RevokeAgentRequest request, HttpServletRequest http) {
        String reason = request == null ? null : request.reason();
        return AgentResponse.of(service.revoke(agentId, reason, ClientInfo.from(http)));
    }
}
