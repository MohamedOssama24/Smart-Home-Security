package com.shsc.scans;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.scans.ScanRepository.ActorType;
import com.shsc.scans.ScanRepository.Changes;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.Status;
import com.shsc.shared.persistence.Sql;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;

/**
 * Reaper of the scans that can no longer progress (allowed periodic job: it never starts a
 * scan and never touches the user's network):
 * <ul>
 * <li>QUEUED whose job was not collected within the queue TTL → FAILED {@code AGENT_OFFLINE};</li>
 * <li>RUNNING whose lease expired (no progress report) → FAILED {@code AGENT_LOST}: results
 * uploaded later are still accepted for 24 hours (LATE_UPLOAD);</li>
 * <li>RUNNING beyond the maximum duration → FAILED {@code TIMEOUT}.</li>
 * </ul>
 * Candidates are listed across tenants by a SECURITY DEFINER function returning only ids;
 * each scan is then re-read and failed in its own tenant-scoped transaction.
 */
@Component
public class ScanReaper {

    private static final Logger LOG = LoggerFactory.getLogger(ScanReaper.class);
    private static final int BATCH = 200;

    private record Due(UUID tenantId, UUID scanId) {
    }

    private final JdbcClient jdbc;
    private final ScanRepository scans;
    private final ScanStateMachine stateMachine;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final Clock clock;

    public ScanReaper(JdbcClient jdbc, ScanRepository scans, ScanStateMachine stateMachine, TenantScope tenantScope,
            TransactionTemplate tx, Clock clock) {
        this.jdbc = jdbc;
        this.scans = scans;
        this.stateMachine = stateMachine;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.clock = clock;
    }

    /** Returns the number of scans failed. */
    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "${shsc.scans.reaper-interval}")
    public int reap() {
        Instant now = clock.instant();
        List<Due> due = tx.execute(status -> jdbc.sql("SELECT tenant_id, scan_id FROM scans_due_for_reaping(:now, :limit)")
                .param("now", Sql.ts(now)).param("limit", BATCH)
                .query((rs, n) -> new Due(Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "scan_id"))).list());
        int failed = 0;
        for (Due d : due) {
            try {
                Boolean done = tenantScope.callAs(d.tenantId(), () -> tx.execute(status -> reapOne(d.scanId(), now)));
                if (Boolean.TRUE.equals(done)) {
                    failed++;
                }
            } catch (ApiException concurrentChange) {
                // the agent or the user changed the scan meanwhile: re-examined at the next run
            }
        }
        if (failed > 0) {
            LOG.info("Scans failed by the reaper: {}", failed);
        }
        return failed;
    }

    private boolean reapOne(UUID scanId, Instant now) {
        Scan scan = scans.lock(scanId).orElse(null);
        if (scan == null) {
            return false;
        }
        String reason = null;
        if (scan.status() == Status.QUEUED && scan.jobExpiresAt().isBefore(now)) {
            reason = "AGENT_OFFLINE";
        } else if (scan.status() == Status.RUNNING && scan.deadlineAt().isBefore(now)) {
            reason = "TIMEOUT";
        } else if (scan.status() == Status.RUNNING && scan.leaseExpiresAt().isBefore(now)) {
            reason = "AGENT_LOST";
        }
        if (reason == null) {
            return false;
        }
        stateMachine.transition(scan, Status.FAILED, Changes.none(), ActorType.SYSTEM, null, reason);
        return true;
    }
}
