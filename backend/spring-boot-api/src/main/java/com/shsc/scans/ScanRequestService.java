package com.shsc.scans;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.agents.management.AgentRepository;
import com.shsc.agents.management.AgentRepository.Agent;
import com.shsc.agents.runtime.AgentRuntimeService;
import com.shsc.agents.runtime.AgentRuntimeService.Connectivity;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.networks.NetworkRepository;
import com.shsc.networks.NetworkRepository.Network;
import com.shsc.scans.ScanRepository.ActorType;
import com.shsc.scans.ScanRepository.Changes;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.Status;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;

/**
 * Single entry point that creates scans (docs/02-MANUAL-SCAN-WORKFLOW.md §3, §6) and user
 * cancellation. In the MVP it is called only by the REST controller, on an explicit user
 * action, with trigger MANUAL: there is no scheduler and the database rejects any other
 * trigger.
 * <p>
 * Validation happens before anything is written, under the home lock (serializes concurrent
 * requests of the same home): permission {@code scan:create} on the home, available profile,
 * at least one authorized network, an ONLINE agent, no other active scan, plan limit. A
 * rejected request answers 4xx and leaves no scan behind. An accepted one is created PENDING
 * and moved to QUEUED in the same transaction, with the authorized networks copied as
 * targets.
 */
@Service
public class ScanRequestService {

    public enum Trigger { MANUAL }

    public enum Profile { DISCOVERY, QUICK, STANDARD }

    public record ScanRequestCommand(UUID homeId, Profile profile, Trigger trigger, String idempotencyKey,
            ClientInfo client) {
    }

    /** The scan and whether it was created by this request (false: same Idempotency-Key). */
    public record ScanRequestResult(Scan scan, boolean created) {
    }

    private final ScanRepository scans;
    private final ScanStateMachine stateMachine;
    private final ScanJobNotifier notifier;
    private final HomeRepository homes;
    private final NetworkRepository networks;
    private final AgentRepository agents;
    private final PlanLimits limits;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final ShscProperties.Scans settings;
    private final Clock clock;

    public ScanRequestService(ScanRepository scans, ScanStateMachine stateMachine, ScanJobNotifier notifier,
            HomeRepository homes, NetworkRepository networks, AgentRepository agents, PlanLimits limits,
            AccessPolicy access, AuditLog audit, ShscProperties properties, Clock clock) {
        this.scans = scans;
        this.stateMachine = stateMachine;
        this.notifier = notifier;
        this.homes = homes;
        this.networks = networks;
        this.agents = agents;
        this.limits = limits;
        this.access = access;
        this.audit = audit;
        this.settings = properties.scans();
        this.clock = clock;
    }

    @Transactional
    public ScanRequestResult request(ScanRequestCommand cmd) {
        if (cmd.trigger() != Trigger.MANUAL) {
            throw new IllegalArgumentException("only manual scans exist in the MVP");
        }
        homes.lock(cmd.homeId()).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.SCAN_CREATE, cmd.homeId());
        if (cmd.idempotencyKey() != null) {
            var previous = scans.findByIdempotencyKey(user.userId(), cmd.idempotencyKey());
            if (previous.isPresent()) {
                if (!previous.get().homeId().equals(cmd.homeId())) {
                    throw ApiException.conflict("IDEMPOTENCY_KEY_REUSED",
                            "This Idempotency-Key was already used for another request.");
                }
                return new ScanRequestResult(previous.get(), false);
            }
        }
        if (cmd.profile() == null) {
            throw ApiException.badRequest("PROFILE_NOT_AVAILABLE", "Choose a scan profile available in this version.");
        }
        List<Network> authorized = networks.forHome(cmd.homeId()).stream()
                .filter(n -> n.authorization() != null).toList();
        if (authorized.isEmpty()) {
            throw ApiException.conflict("NO_AUTHORIZED_NETWORK",
                    "Authorize at least one network of this home before scanning it.");
        }
        Instant now = clock.instant();
        Agent agent = agents.forHome(cmd.homeId()).stream()
                .filter(a -> AgentRuntimeService.connectivity(a, now) == Connectivity.ONLINE)
                .max(Comparator.comparing(Agent::lastHeartbeatAt))
                .orElseThrow(() -> ApiException.conflict("AGENT_OFFLINE",
                        "No agent of this home is online: start the agent and try again."));
        var active = scans.activeOfHome(cmd.homeId());
        if (active.isPresent()) {
            throw new ApiException(HttpStatus.CONFLICT, "SCAN_ALREADY_ACTIVE",
                    "A scan of this home is already in progress.", Map.of("scanId", active.get().id()));
        }
        limits.requireCapacity(Resource.SCANS_PER_DAY, cmd.homeId());

        UUID scanId;
        try {
            scanId = scans.insert(user.tenantId(), cmd.homeId(), agent.id(), cmd.profile().name(), user.userId(),
                    cmd.idempotencyKey(), now);
        } catch (DuplicateKeyException race) {
            throw ApiException.conflict("SCAN_ALREADY_ACTIVE", "A scan of this home is already in progress.");
        }
        for (Network network : authorized) {
            scans.insertTarget(user.tenantId(), scanId, network.id(), network.cidr());
        }
        Scan pending = scans.find(scanId).orElseThrow();
        scans.insertEvent(user.tenantId(), scanId, null, Status.PENDING, ActorType.USER, user.userId(), null, now);
        stateMachine.transition(pending, Status.QUEUED,
                new Changes(now, now.plus(settings.queueTtl()), null, null, null, null, null, null),
                ActorType.USER, user.userId(), null);
        audit.record(AuditEvent.of(AuditAction.SCAN_REQUESTED).tenant(user.tenantId()).user(user.userId())
                .target("SCAN", scanId).client(cmd.client()).detail("homeId", cmd.homeId())
                .detail("profile", cmd.profile().name()).detail("agentId", agent.id())
                .detail("targets", authorized.stream().map(Network::cidr).toList()).build());
        notifier.notifyAfterCommit(agent.id());
        return new ScanRequestResult(scans.find(scanId).orElseThrow(), true);
    }

    /**
     * QUEUED: cancelled at once. RUNNING: the cancellation is requested; the agent receives it
     * in the answer to its next progress report (at most a few seconds later), stops, uploads
     * the partial results and confirms. Terminal: 409.
     */
    @Transactional
    public Scan cancel(UUID scanId, ClientInfo client) {
        Scan scan = scans.lock(scanId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.SCAN_CREATE, scan.homeId());
        switch (scan.status()) {
            case PENDING, QUEUED -> stateMachine.transition(scan, Status.CANCELLED, Changes.none(), ActorType.USER,
                    user.userId(), "USER_CANCELLED");
            case RUNNING -> scans.requestCancel(scanId, user.userId(), clock.instant());
            default -> throw new ApiException(HttpStatus.CONFLICT, "SCAN_ALREADY_FINISHED",
                    "The scan has already finished.", Map.of("status", scan.status().name()));
        }
        audit.record(AuditEvent.of(AuditAction.SCAN_CANCEL_REQUESTED).tenant(user.tenantId()).user(user.userId())
                .target("SCAN", scanId).client(client).detail("homeId", scan.homeId())
                .detail("status", scan.status().name()).build());
        return scans.find(scanId).orElseThrow();
    }

    /** Fails the active scans of an agent being revoked (docs/03-AGENT-PROTOCOL.md §4). */
    @Transactional
    public void failScansOfRevokedAgent(UUID agentId, UUID userId) {
        for (Scan scan : scans.activeOfAgent(agentId)) {
            stateMachine.transition(scan, Status.FAILED, Changes.none(), ActorType.USER, userId, "AGENT_REVOKED");
        }
    }
}
