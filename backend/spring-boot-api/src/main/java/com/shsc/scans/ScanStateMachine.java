package com.shsc.scans;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.shsc.alerts.AlertService;
import com.shsc.scans.ScanRepository.ActorType;
import com.shsc.scans.ScanRepository.Changes;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.Status;
import com.shsc.shared.web.ApiException;

/**
 * The scan state machine of docs/02-MANUAL-SCAN-WORKFLOW.md §2. Every transition is checked
 * against the allowed ones (otherwise 409), written with optimistic locking on
 * {@code version} (a concurrent change, e.g. cancel vs complete, gives 409 instead of a lost
 * update) and recorded in {@code scan_events} with actor and reason.
 * <p>
 * FAILED → COMPLETED_WITH_WARNINGS is the only exit from a terminal state: results uploaded
 * late by an agent whose lease had expired (docs/03-AGENT-PROTOCOL.md §8, LATE_UPLOAD).
 */
@Component
public class ScanStateMachine {

    private static final Map<Status, Set<Status>> ALLOWED = Map.of(
            Status.PENDING, EnumSet.of(Status.QUEUED, Status.FAILED),
            Status.QUEUED, EnumSet.of(Status.RUNNING, Status.CANCELLED, Status.FAILED),
            Status.RUNNING, EnumSet.of(Status.COMPLETED, Status.COMPLETED_WITH_WARNINGS, Status.FAILED,
                    Status.CANCELLED),
            Status.FAILED, EnumSet.of(Status.COMPLETED_WITH_WARNINGS),
            Status.COMPLETED, EnumSet.noneOf(Status.class),
            Status.COMPLETED_WITH_WARNINGS, EnumSet.noneOf(Status.class),
            Status.CANCELLED, EnumSet.noneOf(Status.class));

    private final ScanRepository scans;
    private final AlertService alerts;
    private final Clock clock;

    public ScanStateMachine(ScanRepository scans, AlertService alerts, Clock clock) {
        this.scans = scans;
        this.alerts = alerts;
        this.clock = clock;
    }

    public static boolean allowed(Status from, Status to) {
        return ALLOWED.get(from).contains(to);
    }

    /** Applies the transition and records it; throws 409 if not allowed or if the scan changed meanwhile. */
    public void transition(Scan scan, Status to, Changes changes, ActorType actor, UUID actorId, String reason) {
        if (!allowed(scan.status(), to)) {
            throw new ApiException(HttpStatus.CONFLICT, "INVALID_SCAN_TRANSITION",
                    "The scan cannot go from " + scan.status() + " to " + to + ".",
                    Map.of("status", scan.status().name()));
        }
        Instant now = clock.instant();
        Changes applied = to == Status.FAILED && changes.failureReason() == null
                ? new Changes(changes.queuedAt(), changes.jobExpiresAt(), changes.startedAt(),
                        changes.leaseExpiresAt(), changes.deadlineAt(), changes.completedAt(), reason,
                        changes.warningsJson())
                : changes;
        if (!scans.transition(scan, to, applied, now)) {
            throw ApiException.conflict("SCAN_CHANGED", "The scan changed in the meantime: reload it.");
        }
        scans.insertEvent(scan.tenantId(), scan.id(), scan.status(), to, actor, actorId, reason, now);
        if (to == Status.FAILED) {
            alerts.onScanFailed(scan, reason, now); // M13, same transaction
        }
    }
}
