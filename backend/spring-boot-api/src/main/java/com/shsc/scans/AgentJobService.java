package com.shsc.scans;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.alerts.AlertService;
import com.shsc.agents.auth.AgentAuthService;
import com.shsc.agents.auth.AgentPrincipal;
import com.shsc.integrations.HomeAssistantRepository;
import com.shsc.integrations.HomeAssistantRepository.Inventory;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceFingerprinter;
import com.shsc.findings.SecurityAnalyzer;
import com.shsc.risk.RiskService;
import com.shsc.networks.NetworkRange;
import com.shsc.scans.PortRepository.Port;
import com.shsc.scans.ScanRepository.ActorType;
import com.shsc.scans.ScanRepository.Changes;
import com.shsc.scans.ScanRepository.Observation;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.Status;
import com.shsc.scans.ScanRepository.Target;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.web.ApiException;

import tools.jackson.databind.json.JsonMapper;

/**
 * Agent side of the manual scan workflow (docs/03-AGENT-PROTOCOL.md §6-§8):
 * <ul>
 * <li><b>next job</b>: long polling; the job is signed with the backend key and carries the
 * authorized CIDRs, so the agent can refuse anything else;</li>
 * <li><b>ack</b>: QUEUED → RUNNING with a lease, renewed by every <b>progress</b> report,
 * whose answer carries the user's cancellation request;</li>
 * <li><b>results</b>: idempotent batches (scanId, batchSeq); every observed address must
 * belong to the authorized targets of the scan, otherwise it is dropped, audited and the
 * scan ends with a warning;</li>
 * <li><b>complete</b>: checks that every batch arrived and sets the final state; a completed scan
 * updates the device inventory of the home (fingerprinting, M8) and its security findings
 * (M10).</li>
 * </ul>
 * A scan failed because its lease expired (AGENT_LOST) still accepts the results uploaded
 * within the late-upload window and then becomes COMPLETED_WITH_WARNINGS (LATE_UPLOAD).
 * An agent only sees the scans assigned to it; any other scan answers 404.
 */
@Service
public class AgentJobService {

    public static final int JOB_SCHEMA_VERSION = 1;
    static final int MAX_HOSTS = 1024;
    static final int RATE_PER_SECOND = 50;
    static final int CONCURRENCY = 16;
    private static final Duration RECHECK_EVERY = Duration.ofSeconds(5);
    private static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);
    /** Port scan limits of the QUICK and STANDARD profiles (docs/08 §1). */
    static final Map<String, Object> PORT_LIMITS = Map.of("ratePerSecond", 300, "concurrency", 256,
            "perHostConcurrency", 8, "perHostRatePerSecond", 50, "timeoutMillis", 1500);

    public record SignedJob(String payload, String signature, String keyId) {
    }

    public record Lease(long leaseSeconds, long progressIntervalSeconds) {
    }

    public record ProgressAck(boolean cancelRequested, long leaseSeconds) {
    }

    public record BatchAck(int accepted, int dropped, boolean duplicate) {
    }

    public record CompleteAck(String status) {
    }

    public enum Outcome { COMPLETED, CANCELLED, FAILED }

    private final ScanRepository scans;
    private final PortRepository openPorts;
    private final HomeAssistantRepository homeAssistant;
    private final ScanStateMachine stateMachine;
    private final ScanJobNotifier notifier;
    private final DeviceFingerprinter fingerprinter;
    private final SecurityAnalyzer analyzer;
    private final RiskService risk;
    private final AlertService alerts;
    private final JobSigner signer;
    private final AgentAuthService agentAuth;
    private final AuditLog audit;
    private final TransactionTemplate tx;
    private final JsonMapper json;
    private final ShscProperties.Scans settings;
    private final Clock clock;

    public AgentJobService(ScanRepository scans, PortRepository openPorts, HomeAssistantRepository homeAssistant,
            ScanStateMachine stateMachine,
            ScanJobNotifier notifier, DeviceFingerprinter fingerprinter, SecurityAnalyzer analyzer, RiskService risk,
            AlertService alerts, JobSigner signer,
            AgentAuthService agentAuth, AuditLog audit,
            TransactionTemplate tx, JsonMapper json,
            ShscProperties properties, Clock clock) {
        this.scans = scans;
        this.openPorts = openPorts;
        this.homeAssistant = homeAssistant;
        this.stateMachine = stateMachine;
        this.notifier = notifier;
        this.fingerprinter = fingerprinter;
        this.analyzer = analyzer;
        this.risk = risk;
        this.alerts = alerts;
        this.signer = signer;
        this.agentAuth = agentAuth;
        this.audit = audit;
        this.tx = tx;
        this.json = json;
        this.settings = properties.scans();
        this.clock = clock;
    }

    /** Waits up to {@code wait} for a queued job of this agent; empty = nothing to do (204). */
    public Optional<SignedJob> nextJob(AgentPrincipal agent, Duration wait) throws InterruptedException {
        Duration max = wait.compareTo(settings.longPollMax()) > 0 ? settings.longPollMax() : wait;
        Instant deadline = clock.instant().plus(max);
        while (true) {
            agentAuth.requireHome(agent); // a revoked agent stops waiting with 401
            Optional<SignedJob> job = tx.execute(status -> scans.nextQueued(agent.agentId(), clock.instant())
                    .map(this::sign));
            Duration left = Duration.between(clock.instant(), deadline);
            if (job.isPresent() || left.isNegative() || left.isZero()) {
                return job;
            }
            notifier.await(agent.agentId(), left.compareTo(RECHECK_EVERY) < 0 ? left : RECHECK_EVERY);
        }
    }

    public Lease ack(AgentPrincipal agent, UUID scanId) {
        agentAuth.requireHome(agent);
        return tx.execute(status -> {
            Scan scan = ownScan(agent, scanId);
            Instant now = clock.instant();
            Instant lease = now.plus(settings.lease());
            if (scan.status() == Status.RUNNING) {
                // repeated ack (answer lost): idempotent, renews the lease
                scans.recordProgress(scanId, scan.progressJson() == null ? "{}" : scan.progressJson(),
                        scan.devicesDiscovered(), lease);
            } else if (scan.status() == Status.QUEUED) {
                stateMachine.transition(scan, Status.RUNNING,
                        new Changes(null, null, now, lease, now.plus(settings.maxDuration()), null, null, null),
                        ActorType.AGENT, agent.agentId(), null);
            } else {
                throw notRunning(scan);
            }
            return new Lease(settings.lease().toSeconds(), settings.progressInterval().toSeconds());
        });
    }

    public ProgressAck progress(AgentPrincipal agent, UUID scanId, String phase, int percent, int devicesDiscovered) {
        agentAuth.requireHome(agent);
        return tx.execute(status -> {
            Scan scan = ownScan(agent, scanId);
            if (scan.status() != Status.RUNNING) {
                throw notRunning(scan);
            }
            String progress = json.writeValueAsString(Map.of("phase", phase, "percent", percent));
            scans.recordProgress(scanId, progress, devicesDiscovered, clock.instant().plus(settings.lease()));
            return new ProgressAck(scan.cancelRequestedAt() != null, settings.lease().toSeconds());
        });
    }

    public BatchAck results(AgentPrincipal agent, UUID scanId, int batchSeq, List<Observation> observations,
            List<Port> ports, Inventory inventory, String rawBody) {
        agentAuth.requireHome(agent);
        return tx.execute(status -> {
            Scan scan = ownScan(agent, scanId);
            Instant now = clock.instant();
            boolean late = acceptsLateResults(scan, now);
            if (scan.status() != Status.RUNNING && !late) {
                throw notAccepting(scan);
            }
            List<NetworkRange> targets = scans.targets(scanId).stream().map(Target::cidr).map(NetworkRange::parse)
                    .toList();
            List<Observation> inScope = new ArrayList<>();
            Set<String> outOfScope = new LinkedHashSet<>();
            for (Observation o : observations) {
                if (targets.stream().anyMatch(t -> t.contains(o.ip()))) {
                    Instant at = o.observedAt().isAfter(now.plus(MAX_FUTURE_SKEW)) ? now : o.observedAt();
                    inScope.add(new Observation(o.ip(), o.mac(), o.method(), o.iface(), o.hostname(), o.details(), at));
                } else {
                    outOfScope.add(o.ip());
                }
            }
            if (!portProfile(scan) && (!ports.isEmpty()
                    || observations.stream().anyMatch(o -> "PORTSCAN".equals(o.method())))) {
                throw ApiException.badRequest("PORTS_NOT_EXPECTED", "The profile of this scan does not scan ports.");
            }
            List<Port> portsInScope = new ArrayList<>();
            for (Port p : ports) {
                if (targets.stream().anyMatch(t -> t.contains(p.ip()))) {
                    Instant at = p.observedAt().isAfter(now.plus(MAX_FUTURE_SKEW)) ? now : p.observedAt();
                    portsInScope.add(new Port(p.ip(), p.protocol(), p.port(), p.state(), p.reason(), at, p.service()));
                } else {
                    outOfScope.add(p.ip());
                }
            }
            // Home Assistant must be on an authorized network of the scan, like every other host (docs/24 §2)
            Inventory haInScope = null;
            if (inventory != null) {
                if (targets.stream().anyMatch(t -> t.contains(inventory.ip()))) {
                    Instant at = inventory.observedAt().isAfter(now.plus(MAX_FUTURE_SKEW)) ? now
                            : inventory.observedAt();
                    haInScope = new Inventory(inventory.ip(), inventory.version(), inventory.https(), at,
                            inventory.devices(), inventory.truncated());
                } else {
                    outOfScope.add(inventory.ip());
                }
            }
            int dropped = outOfScope.size(); // distinct addresses, as in M6-M8
            String sha = HexFormat.of().formatHex(SecureTokens.sha256(rawBody));
            if (!scans.insertBatch(scan.tenantId(), scanId, batchSeq, sha, inScope.size(), portsInScope.size(), dropped,
                    late, now)) {
                return new BatchAck(0, 0, true); // already received: no-op
            }
            inScope.forEach(o -> scans.insertObservation(scan.tenantId(), scanId, o));
            portsInScope.forEach(p -> openPorts.insert(scan.tenantId(), scanId, p));
            if (haInScope != null && !homeAssistant.insert(scan.tenantId(), scanId, haInScope)) {
                throw ApiException.conflict("HOME_ASSISTANT_ALREADY_UPLOADED",
                        "The Home Assistant inventory of this scan was already received.");
            }
            scans.refreshCounters(scanId, dropped);
            if (!outOfScope.isEmpty()) {
                audit.record(AuditEvent.of(AuditAction.SCAN_RESULTS_OUT_OF_SCOPE).tenant(scan.tenantId())
                        .agent(agent.agentId()).target("SCAN", scanId).detail("homeId", scan.homeId())
                        .detail("batchSeq", batchSeq).detail("dropped", dropped)
                        .detail("addresses", outOfScope.stream().limit(10).toList()).build());
            }
            return new BatchAck(inScope.size() + portsInScope.size() + (haInScope == null ? 0 : 1), dropped, false);
        });
    }

    public CompleteAck complete(AgentPrincipal agent, UUID scanId, int totalBatches, Outcome outcome,
            List<String> agentWarnings, String errorCode) {
        agentAuth.requireHome(agent);
        return tx.execute(status -> {
            Scan scan = ownScan(agent, scanId);
            Instant now = clock.instant();
            if (scan.status() == Status.COMPLETED || scan.status() == Status.COMPLETED_WITH_WARNINGS
                    || scan.status() == Status.CANCELLED) {
                return new CompleteAck(scan.status().name()); // repeated complete (answer lost)
            }
            boolean late = acceptsLateResults(scan, now);
            if (scan.status() != Status.RUNNING && !late) {
                throw notAccepting(scan);
            }
            List<Integer> received = scans.batchNumbers(scanId);
            List<Integer> missing = IntStream.range(0, totalBatches).filter(i -> !received.contains(i)).boxed()
                    .limit(50).toList();
            if (!missing.isEmpty() || received.size() != totalBatches) {
                throw new ApiException(HttpStatus.CONFLICT, "MISSING_BATCHES",
                        "Not every result batch has been received.", Map.of("missing", missing));
            }
            scans.setTotalBatches(scanId, totalBatches);
            Scan current = scans.lock(scanId).orElseThrow();
            Set<String> warnings = new LinkedHashSet<>(agentWarnings);
            if (current.outOfScopeDropped() > 0) {
                warnings.add("OUT_OF_SCOPE_RESULTS");
            }
            if (late) {
                if (outcome == Outcome.COMPLETED) {
                    warnings.add("LATE_UPLOAD");
                    stateMachine.transition(current, Status.COMPLETED_WITH_WARNINGS, warnings(warnings),
                            ActorType.AGENT, agent.agentId(), "LATE_UPLOAD");
                    fingerprinter.fingerprint(current, now);
                    // security analysis of the devices seen (M10), same transaction
                    analyzer.analyze(current, now);
                    // security score, coverage, snapshot and delta (M11), then the alerts (M13): same transaction
                    alerts.onScanCompleted(current, risk.computeForScan(current, now), now);
                }
                // a late cancelled/failed scan stays FAILED: its partial results are kept
                return new CompleteAck(scans.find(scanId).orElseThrow().status().name());
            }
            switch (outcome) {
                case COMPLETED -> {
                    stateMachine.transition(current,
                            warnings.isEmpty() ? Status.COMPLETED : Status.COMPLETED_WITH_WARNINGS, warnings(warnings),
                            ActorType.AGENT, agent.agentId(), null);
                    // device inventory and classification (M8), in the same transaction
                    fingerprinter.fingerprint(current, now);
                    // security analysis of the devices seen (M10), same transaction
                    analyzer.analyze(current, now);
                    // security score, coverage, snapshot and delta (M11), then the alerts (M13): same transaction
                    alerts.onScanCompleted(current, risk.computeForScan(current, now), now);
                }
                case CANCELLED -> {
                    if (current.cancelRequestedAt() != null) {
                        stateMachine.transition(current, Status.CANCELLED, warnings(warnings), ActorType.AGENT,
                                agent.agentId(), "USER_CANCELLED");
                    } else {
                        // stopped by the agent itself (e.g. service shutdown), not by the user
                        stateMachine.transition(current, Status.FAILED, warnings(warnings), ActorType.AGENT,
                                agent.agentId(), "AGENT_ABORTED");
                    }
                }
                case FAILED -> stateMachine.transition(current, Status.FAILED, warnings(warnings), ActorType.AGENT,
                        agent.agentId(), errorCode == null ? "AGENT_ERROR" : errorCode);
            }
            return new CompleteAck(scans.find(scanId).orElseThrow().status().name());
        });
    }

    /** QUICK and STANDARD scan the ports of the discovered hosts. */
    static boolean portProfile(Scan scan) {
        return !ScanRequestService.Profile.DISCOVERY.name().equals(scan.profile());
    }

    /** FAILED because the lease expired, within the late-upload window. */
    private boolean acceptsLateResults(Scan scan, Instant now) {
        return scan.status() == Status.FAILED && "AGENT_LOST".equals(scan.failureReason())
                && scan.completedAt() != null && scan.completedAt().plus(settings.lateUploadWindow()).isAfter(now);
    }

    private Scan ownScan(AgentPrincipal agent, UUID scanId) {
        return scans.lock(scanId).filter(s -> s.agentId().equals(agent.agentId()))
                .orElseThrow(ApiException::notFound);
    }

    private Changes warnings(Set<String> warnings) {
        return new Changes(null, null, null, null, null, null, null,
                json.writeValueAsString(List.copyOf(warnings)));
    }

    private SignedJob sign(Scan scan) {
        Map<String, Object> job = new LinkedHashMap<>();
        job.put("schemaVersion", JOB_SCHEMA_VERSION);
        job.put("scanId", scan.id());
        job.put("agentId", scan.agentId());
        job.put("homeId", scan.homeId());
        job.put("profile", scan.profile());
        job.put("targets", scans.targets(scan.id()).stream()
                .map(t -> Map.of("networkId", t.networkId(), "cidr", t.cidr())).toList());
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("maxHosts", MAX_HOSTS);
        limits.put("ratePerSecond", RATE_PER_SECOND);
        limits.put("concurrency", CONCURRENCY);
        limits.put("maxDurationSeconds", settings.maxDuration().toSeconds());
        if (portProfile(scan)) {
            limits.put("ports", PORT_LIMITS); // docs/08 §1, also enforced by the agent
        }
        job.put("limits", limits);
        job.put("issuedAt", clock.instant().toString());
        job.put("expiresAt", scan.jobExpiresAt().toString());
        byte[] payload = json.writeValueAsString(job).getBytes(StandardCharsets.UTF_8);
        return new SignedJob(Base64.getUrlEncoder().withoutPadding().encodeToString(payload),
                signer.sign(payload), signer.keyId());
    }

    private static ApiException notRunning(Scan scan) {
        return new ApiException(HttpStatus.CONFLICT, "SCAN_NOT_RUNNING", "The scan is not running.",
                Map.of("status", scan.status().name()));
    }

    private static ApiException notAccepting(Scan scan) {
        return new ApiException(HttpStatus.CONFLICT, "SCAN_NOT_ACCEPTING_RESULTS",
                "The scan does not accept results any more.", Map.of("status", scan.status().name()));
    }
}
