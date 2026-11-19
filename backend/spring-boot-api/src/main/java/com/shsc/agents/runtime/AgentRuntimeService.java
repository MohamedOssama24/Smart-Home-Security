package com.shsc.agents.runtime;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.agents.auth.AgentAuthService;
import com.shsc.agents.auth.AgentPrincipal;
import com.shsc.agents.management.AgentRepository;
import com.shsc.alerts.AlertService;
import com.shsc.agents.management.AgentRepository.Agent;
import com.shsc.agents.management.AgentRepository.AgentStatus;
import com.shsc.agents.management.AgentRepository.Heartbeat;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.web.ApiException;

import tools.jackson.databind.json.JsonMapper;

/**
 * Agent side of the runtime protocol (docs/03-AGENT-PROTOCOL.md §5, §8): heartbeats with the
 * self-diagnosis and delivery of the events queued locally by the agent. Every call re-checks
 * that the agent is still active and bound to its home, so a revoked agent gets
 * {@code 401 AGENT_REVOKED} at its next heartbeat (at most 25 s later).
 */
@Service
public class AgentRuntimeService {

    /** Connectivity shown to users, computed from the last heartbeat. */
    public enum Connectivity { ONLINE, STALE, OFFLINE, NEVER_CONNECTED, REVOKED }

    public static final Duration ONLINE_WITHIN = Duration.ofMinutes(3);
    public static final Duration STALE_WITHIN = Duration.ofMinutes(15);
    static final int MAX_EVENTS_PER_AGENT = 500;
    static final int MAX_DETAIL_BYTES = 4096;
    private static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);

    public record HeartbeatAck(Instant serverTime, long heartbeatIntervalSeconds) {
    }

    public record IncomingEvent(UUID id, String type, Instant occurredAt, Map<String, Object> detail) {
    }

    public record EventsAck(int accepted, int duplicates) {
    }

    private final AgentRepository agents;
    private final AgentAuthService agentAuth;
    private final JsonMapper json;
    private final ShscProperties.Agent settings;
    private final AlertService alerts;
    private final Clock clock;

    public AgentRuntimeService(AgentRepository agents, AgentAuthService agentAuth, JsonMapper json,
            ShscProperties properties, AlertService alerts, Clock clock) {
        this.alerts = alerts;
        this.agents = agents;
        this.agentAuth = agentAuth;
        this.json = json;
        this.settings = properties.agent();
        this.clock = clock;
    }

    @Transactional
    public HeartbeatAck heartbeat(AgentPrincipal principal, Heartbeat heartbeat) {
        agentAuth.requireHome(principal);
        Instant now = clock.instant();
        agents.recordHeartbeat(principal.agentId(), heartbeat, now);
        alerts.onHeartbeat(principal.agentId(), now); // resolves its AGENT_OFFLINE alert, if any (M13)
        return new HeartbeatAck(now, settings.heartbeatInterval().toSeconds());
    }

    /** Stores the events not seen before; re-sent events are counted as duplicates. */
    @Transactional
    public EventsAck events(AgentPrincipal principal, List<IncomingEvent> events) {
        agentAuth.requireHome(principal);
        Instant now = clock.instant();
        int accepted = 0;
        for (IncomingEvent event : events) {
            String detail = json.writeValueAsString(event.detail() == null ? Map.of() : event.detail());
            if (detail.length() > MAX_DETAIL_BYTES) {
                throw ApiException.badRequest("INVALID_EVENT", "The detail of an event is too large.");
            }
            // a wrong agent clock must not place events in the future
            Instant occurredAt = event.occurredAt().isAfter(now.plus(MAX_FUTURE_SKEW)) ? now : event.occurredAt();
            if (agents.insertEvent(principal.tenantId(), principal.agentId(), event.id(), event.type(), occurredAt,
                    detail, now)) {
                accepted++;
            }
        }
        if (accepted > 0) {
            agents.trimEvents(principal.agentId(), MAX_EVENTS_PER_AGENT);
        }
        return new EventsAck(accepted, events.size() - accepted);
    }

    /** ONLINE (heartbeat < 3 min), STALE (< 15 min), OFFLINE, NEVER_CONNECTED or REVOKED. */
    public static Connectivity connectivity(Agent agent, Instant now) {
        if (agent.status() == AgentStatus.REVOKED) {
            return Connectivity.REVOKED;
        }
        if (agent.lastHeartbeatAt() == null) {
            return Connectivity.NEVER_CONNECTED;
        }
        Duration age = Duration.between(agent.lastHeartbeatAt(), now);
        if (age.compareTo(ONLINE_WITHIN) < 0) {
            return Connectivity.ONLINE;
        }
        return age.compareTo(STALE_WITHIN) < 0 ? Connectivity.STALE : Connectivity.OFFLINE;
    }
}
