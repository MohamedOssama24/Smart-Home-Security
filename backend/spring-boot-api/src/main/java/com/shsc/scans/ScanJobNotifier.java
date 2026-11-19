package com.shsc.scans;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * In-process wake-up of the agents waiting in {@code GET /agent/jobs/next} (long polling):
 * when a scan is queued, the request of its agent returns at once instead of at the end of
 * the wait. The database stays the source of truth: a waiting request re-reads it after
 * every wake-up and at least every few seconds, so a lost notification (or a second backend
 * instance) only delays the job, it never loses it.
 */
@Component
public class ScanJobNotifier {

    private final ConcurrentMap<UUID, CompletableFuture<Void>> waiting = new ConcurrentHashMap<>();

    /** Blocks the calling (virtual) thread until notified or until {@code max} elapses. */
    public void await(UUID agentId, Duration max) throws InterruptedException {
        CompletableFuture<Void> signal = waiting.computeIfAbsent(agentId, id -> new CompletableFuture<>());
        try {
            signal.get(max.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException | ExecutionException e) {
            // timeout: the caller checks the database again
        }
    }

    /** Wakes up the agent after the current transaction commits (the job is visible by then). */
    public void notifyAfterCommit(UUID agentId) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            wake(agentId);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                wake(agentId);
            }
        });
    }

    private void wake(UUID agentId) {
        CompletableFuture<Void> signal = waiting.remove(agentId);
        if (signal != null) {
            signal.complete(null);
        }
    }
}
