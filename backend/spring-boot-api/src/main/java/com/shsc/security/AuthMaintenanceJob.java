package com.shsc.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.shared.config.ShscProperties;

/**
 * Maintenance only (allowed periodic job, never a scan): deletes expired authentication
 * material (used/expired refresh tokens, e-mail tokens, agent tokens, anti-replay ids,
 * stale throttling counters) older than the retention period.
 */
@Component
public class AuthMaintenanceJob {

    private static final Logger LOG = LoggerFactory.getLogger(AuthMaintenanceJob.class);

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final ShscProperties.Maintenance settings;

    public AuthMaintenanceJob(JdbcClient jdbc, TransactionTemplate tx, ShscProperties properties) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.settings = properties.security().maintenance();
    }

    @Scheduled(initialDelayString = "PT5M", fixedDelayString = "${shsc.security.maintenance.purge-interval}")
    public void purge() {
        Long deleted = tx.execute(status -> jdbc.sql("SELECT purge_expired_auth_data(CAST(:retention AS interval))")
                .param("retention", settings.purgeRetention().toSeconds() + " seconds")
                .query(Long.class).single());
        LOG.info("Expired authentication data purged: {} rows", deleted);
    }
}
