package com.shsc.agents.management;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.agents.management.AgentRepository.Agent;
import com.shsc.agents.management.AgentRepository.AgentEvent;
import com.shsc.agents.management.AgentRepository.EnrollmentToken;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.scans.ScanRequestService;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;

/** User-side agent administration: enrollment tokens, agent list, revocation. */
@Service
public class AgentManagementService {

    public record CreatedEnrollmentToken(EnrollmentToken token, String secret) {
    }

    private final AgentRepository agents;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final PlanLimits limits;
    private final ShscProperties.Agent settings;
    private final Clock clock;
    private final ScanRequestService scanRequests;

    public AgentManagementService(AgentRepository agents, HomeRepository homes, AccessPolicy access, AuditLog audit,
            PlanLimits limits, ShscProperties properties, Clock clock, ScanRequestService scanRequests) {
        this.scanRequests = scanRequests;
        this.limits = limits;
        this.agents = agents;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.settings = properties.agent();
        this.clock = clock;
    }

    /** Creates a one-time enrollment token for a home. The secret is returned only here. */
    @Transactional
    public CreatedEnrollmentToken createEnrollmentToken(UUID homeId, ClientInfo client) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.AGENT_ENROLL, homeId);
        // early feedback; the authoritative check is repeated when the agent enrolls
        limits.requireCapacity(Resource.AGENTS_PER_HOME, homeId);
        Instant now = clock.instant();
        String secret = SecureTokens.generate(SecureTokens.ENROLLMENT_TOKEN_PREFIX);
        EnrollmentToken token = agents.insertEnrollmentToken(user.tenantId(), homeId, SecureTokens.sha256(secret),
                user.userId(), now, now.plus(settings.enrollmentTokenTtl()));
        audit.record(AuditEvent.of(AuditAction.AGENT_ENROLLMENT_TOKEN_CREATED).tenant(user.tenantId())
                .user(user.userId()).target("HOME", homeId).client(client).detail("tokenId", token.id())
                .detail("expiresAt", token.expiresAt().toString()).build());
        return new CreatedEnrollmentToken(token, secret);
    }

    @Transactional(readOnly = true)
    public List<EnrollmentToken> enrollmentTokens(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.AGENT_READ, homeId);
        return agents.enrollmentTokens(homeId);
    }

    @Transactional
    public void revokeEnrollmentToken(UUID tokenId, ClientInfo client) {
        EnrollmentToken token = agents.lockEnrollmentToken(tokenId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.AGENT_REVOKE, token.homeId());
        if (token.usedAt() != null) {
            throw ApiException.conflict("TOKEN_ALREADY_USED", "The enrollment token was already used.");
        }
        agents.revokeEnrollmentToken(tokenId, user.userId(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.AGENT_ENROLLMENT_TOKEN_REVOKED).tenant(user.tenantId())
                .user(user.userId()).target("HOME", token.homeId()).client(client).detail("tokenId", tokenId).build());
    }

    @Transactional(readOnly = true)
    public List<Agent> agentsOfHome(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.AGENT_READ, homeId);
        return agents.forHome(homeId);
    }

    @Transactional(readOnly = true)
    public Agent agent(UUID agentId) {
        Agent agent = agents.find(agentId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.AGENT_READ, agent.homeId());
        return agent;
    }

    @Transactional(readOnly = true)
    public List<AgentEvent> events(UUID agentId) {
        Agent agent = agents.find(agentId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.AGENT_READ, agent.homeId());
        return agents.events(agentId, 50);
    }

    /** Revokes the agent: credentials and access tokens stop working at the next request. */
    @Transactional
    public Agent revoke(UUID agentId, String reason, ClientInfo client) {
        Agent agent = agents.lock(agentId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.AGENT_REVOKE, agent.homeId());
        if (agent.status() == AgentRepository.AgentStatus.REVOKED) {
            return agent;
        }
        agents.revokeAgent(agentId, user.userId(), reason, clock.instant());
        // its active scans cannot complete any more
        scanRequests.failScansOfRevokedAgent(agentId, user.userId());
        audit.record(AuditEvent.of(AuditAction.AGENT_REVOKED).tenant(user.tenantId()).user(user.userId())
                .target("AGENT", agentId).client(client).detail("homeId", agent.homeId()).detail("reason", reason)
                .build());
        return agents.find(agentId).orElseThrow();
    }
}
