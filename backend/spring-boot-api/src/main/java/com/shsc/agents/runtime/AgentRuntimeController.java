package com.shsc.agents.runtime;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.agents.auth.AgentPrincipal;
import com.shsc.agents.management.AgentRepository.Heartbeat;
import com.shsc.agents.runtime.AgentRuntimeService.EventsAck;
import com.shsc.agents.runtime.AgentRuntimeService.HeartbeatAck;
import com.shsc.agents.runtime.AgentRuntimeService.IncomingEvent;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.json.JsonMapper;

/** Agent runtime API: heartbeat and queued events (agent access token only). */
@RestController
@RequestMapping("/api/v1/agent")
public class AgentRuntimeController {

    /** Message schema versions accepted (N and N-1; only 1 exists so far). */
    static final int SCHEMA_MIN = 1;
    static final int SCHEMA_MAX = 1;

    public record NetworkInterface(
            @NotBlank @Size(max = 64) String name,
            @Pattern(regexp = "[0-9a-f]{2}(:[0-9a-f]{2}){5,19}") String mac,
            @PositiveOrZero @Max(1_000_000) int mtu,
            @NotNull @Size(min = 1, max = 16) List<@NotNull @Pattern(regexp = "[0-9a-fA-F.:]{2,45}/[0-9]{1,3}") String> addresses) {
    }

    public record Capabilities(
            boolean privileged,
            @NotNull @Pattern(regexp = "raw|os_api|os_table|unavailable") String arp,
            @NotNull @Pattern(regexp = "raw|unprivileged|os_api|unavailable") String icmp,
            @NotNull @Size(max = 10) List<@NotNull @Pattern(regexp = "[A-Z_]{1,40}") String> warnings,
            // router integrations configured on the agent (names only; null for agents before M7)
            @Size(max = 2) List<@NotNull @Pattern(regexp = "TR064|SNMP") String> routerIntegrations) {
    }

    public record HeartbeatRequest(
            @NotNull @Min(SCHEMA_MIN) @Max(SCHEMA_MAX) Integer schemaVersion,
            @NotBlank @Size(max = 64) @Pattern(regexp = "[0-9A-Za-z.+_-]+") String agentVersion,
            @NotNull @PositiveOrZero Long uptimeSeconds,
            @NotNull @Pattern(regexp = "[0-9a-f]{64}") String interfacesHash,
            @Size(max = 32) List<@NotNull @Valid NetworkInterface> interfaces,
            @NotNull @Valid Capabilities capabilities,
            @NotNull @PositiveOrZero @Max(100_000_000) Integer queueDepth,
            @Size(max = 300) String lastError) {
    }

    public record EventItem(
            @NotNull UUID id,
            @NotNull @Pattern(regexp = "AGENT_STARTED|AGENT_STOPPED|CAPABILITIES_CHANGED|CONNECTION_RESTORED|QUEUE_OVERFLOW") String type,
            @NotNull Instant occurredAt,
            Map<String, Object> detail) {
    }

    public record EventsRequest(
            @NotNull @Min(SCHEMA_MIN) @Max(SCHEMA_MAX) Integer schemaVersion,
            @NotNull @Size(min = 1, max = 100) List<@NotNull @Valid EventItem> events) {
    }

    private final AgentRuntimeService runtime;
    private final JsonMapper json;

    public AgentRuntimeController(AgentRuntimeService runtime, JsonMapper json) {
        this.runtime = runtime;
        this.json = json;
    }

    @PostMapping("/heartbeat")
    public HeartbeatAck heartbeat(@AuthenticationPrincipal AgentPrincipal agent,
            @Valid @RequestBody HeartbeatRequest request) {
        String lastError = request.lastError() == null || request.lastError().isBlank() ? null : request.lastError();
        String interfaces = request.interfaces() == null ? null : json.writeValueAsString(request.interfaces());
        return runtime.heartbeat(agent, new Heartbeat(request.agentVersion(), request.uptimeSeconds(),
                request.interfacesHash(), interfaces, json.writeValueAsString(request.capabilities()),
                request.queueDepth(), lastError));
    }

    @PostMapping("/events")
    public EventsAck events(@AuthenticationPrincipal AgentPrincipal agent, @Valid @RequestBody EventsRequest request) {
        return runtime.events(agent, request.events().stream()
                .map(e -> new IncomingEvent(e.id(), e.type(), e.occurredAt(), e.detail())).toList());
    }
}
