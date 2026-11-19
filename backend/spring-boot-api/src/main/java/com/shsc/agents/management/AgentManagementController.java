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
import com.shsc.agents.runtime.AgentRuntimeService;
import com.shsc.agents.runtime.AgentRuntimeService.Connectivity;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

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

    /** Agent with its connectivity and the self-diagnosis of its last heartbeat. */
    public record AgentResponse(UUID id, UUID homeId, String name, String hostname, String os, String arch,
            String agentVersion, String status, Instant enrolledAt, Instant lastSeenAt, Instant revokedAt,
            String revokeReason, Connectivity connectivity, Instant lastHeartbeatAt, JsonNode capabilities,
            JsonNode interfaces, Integer queueDepth, Long uptimeSeconds, String lastError) {
    }

    public record AgentEventResponse(UUID id, String type, Instant occurredAt, Instant receivedAt, JsonNode detail) {
    }

    public record RevokeAgentRequest(@Size(max = 200) String reason) {
    }

    private final AgentManagementService service;
    private final JsonMapper json;
    private final Clock clock;

    public AgentManagementController(AgentManagementService service, JsonMapper json, Clock clock) {
        this.service = service;
        this.json = json;
        this.clock = clock;
    }

    private AgentResponse toResponse(Agent a) {
        return new AgentResponse(a.id(), a.homeId(), a.name(), a.hostname(), a.os(), a.arch(), a.agentVersion(),
                a.status().name(), a.enrolledAt(), a.lastSeenAt(), a.revokedAt(), a.revokeReason(),
                AgentRuntimeService.connectivity(a, clock.instant()), a.lastHeartbeatAt(), parse(a.capabilitiesJson()),
                parse(a.interfacesJson()), a.queueDepth(), a.uptimeSeconds(), a.lastError());
    }

    private JsonNode parse(String value) {
        return value == null ? null : json.readTree(value);
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
        return service.agentsOfHome(homeId).stream().map(this::toResponse).toList();
    }

    @GetMapping("/api/v1/agents/{agentId}")
    public AgentResponse agent(@PathVariable UUID agentId) {
        return toResponse(service.agent(agentId));
    }

    @PostMapping("/api/v1/agents/{agentId}/revoke")
    public AgentResponse revoke(@PathVariable UUID agentId,
            @Valid @RequestBody(required = false) RevokeAgentRequest request, HttpServletRequest http) {
        String reason = request == null ? null : request.reason();
        return toResponse(service.revoke(agentId, reason, ClientInfo.from(http)));
    }

    /** Most recent events delivered by the agent (newest first). */
    @GetMapping("/api/v1/agents/{agentId}/events")
    public List<AgentEventResponse> events(@PathVariable UUID agentId) {
        return service.events(agentId).stream().map(e -> new AgentEventResponse(e.eventId(), e.type(), e.occurredAt(),
                e.receivedAt(), parse(e.detailJson()))).toList();
    }
}
