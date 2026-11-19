package com.shsc.alerts;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiFunction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.agents.runtime.AgentRuntimeService;
import com.shsc.alerts.AlertRepository.DeliveryJob;
import com.shsc.alerts.AlertType.Channel;
import com.shsc.alerts.push.PushDeviceRepository;
import com.shsc.alerts.push.PushDeviceRepository.PushDevice;
import com.shsc.alerts.push.PushGateway;
import com.shsc.shared.persistence.Sql;
import com.shsc.shared.persistence.TenantScope;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Periodic alert jobs (they never touch the users' networks):
 * <ul>
 * <li>e-mail dispatch: pending EMAIL deliveries are sent through SMTP; a failure is retried after
 * 5 and 15 minutes, then the delivery is FAILED (the alert stays in the dashboard);</li>
 * <li>push dispatch: pending PUSH deliveries are sent through FCM to the user's app installations,
 * with the same retries ({@code PUSH_ERROR}); invalid tokens are removed;</li>
 * <li>agent offline: an active agent without heartbeat for 15 minutes raises AGENT_OFFLINE once
 * (resolved by its next heartbeat).</li>
 * </ul>
 * Candidates are listed across tenants by SECURITY DEFINER functions returning only ids; each one
 * is processed in its own tenant-scoped transaction.
 */
@Component
public class AlertJobs {

    private static final Logger LOG = LoggerFactory.getLogger(AlertJobs.class);
    static final int MAX_ATTEMPTS = 3;
    private static final List<Duration> RETRY = List.of(Duration.ofMinutes(5), Duration.ofMinutes(15));
    private static final int BATCH = 100;

    private record Due(UUID tenantId, UUID id) {
    }

    private final JdbcClient jdbc;
    private final AlertRepository alerts;
    private final AlertService service;
    private final AlertMailer mailer;
    private final JavaMailSender sender;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final PushGateway push;
    private final PushDeviceRepository pushDevices;
    private final JsonMapper json;

    public AlertJobs(JdbcClient jdbc, AlertRepository alerts, AlertService service, AlertMailer mailer,
            JavaMailSender sender, TenantScope tenantScope, TransactionTemplate tx, Clock clock, PushGateway push,
            PushDeviceRepository pushDevices, JsonMapper json) {
        this.jdbc = jdbc;
        this.alerts = alerts;
        this.service = service;
        this.mailer = mailer;
        this.sender = sender;
        this.push = push;
        this.pushDevices = pushDevices;
        this.json = json;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.clock = clock;
    }

    /** Returns the number of e-mails sent. */
    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "${shsc.alerts.dispatch-interval:PT30S}")
    public int dispatchEmails() {
        return dispatch(Channel.EMAIL, this::sendEmail);
    }

    /** Returns the number of alerts pushed to at least one app installation. */
    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "${shsc.alerts.dispatch-interval:PT30S}")
    public int dispatchPushes() {
        return dispatch(Channel.PUSH, this::sendPush);
    }

    private int dispatch(Channel channel, BiFunction<DeliveryJob, Integer, Boolean> send) {
        Instant now = clock.instant();
        List<Due> due = tx.execute(status -> jdbc.sql(
                        "SELECT tenant_id, delivery_id FROM alert_deliveries_due(:channel, :now, :limit)")
                .param("channel", channel.name()).param("now", Sql.ts(now)).param("limit", BATCH)
                .query((rs, n) -> new Due(Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "delivery_id"))).list());
        int sent = 0;
        for (Due d : due) {
            Boolean ok = tenantScope.callAs(d.tenantId(), () -> tx.execute(status -> {
                DeliveryJob job = alerts.lockDelivery(d.id(), channel).orElse(null);
                if (job == null) {
                    return false; // sent by another instance meanwhile
                }
                int attempts = job.attempts() + 1;
                if (!"ACTIVE".equals(job.userStatus())) {
                    alerts.deliveryNotSent(job.deliveryId(), attempts, "USER_INACTIVE", null);
                    return false;
                }
                return send.apply(job, attempts);
            }));
            if (Boolean.TRUE.equals(ok)) {
                sent++;
            }
        }
        if (!due.isEmpty()) {
            LOG.info("Alert {} deliveries: {} due, {} sent", channel, due.size(), sent);
        }
        return sent;
    }

    private boolean sendEmail(DeliveryJob job, int attempts) {
        try {
            sender.send(mailer.build(job));
            alerts.deliverySent(job.deliveryId(), attempts, clock.instant());
            return true;
        } catch (MailException e) {
            // the address and the text are not logged
            LOG.warn("Alert e-mail {} not sent (attempt {}): {}", job.deliveryId(), attempts,
                    e.getClass().getSimpleName());
            retryOrFail(job, attempts, "SMTP_ERROR");
            return false;
        }
    }

    /**
     * One notification per app installation of the user whose login session is still valid; the
     * delivery is SENT if at least one installation accepted it. Invalid tokens are removed.
     */
    private boolean sendPush(DeliveryJob job, int attempts) {
        List<PushDevice> targets = pushDevices.activeOfUser(job.userId(), clock.instant());
        boolean sent = false;
        boolean temporary = false;
        for (PushDevice device : targets) {
            JsonNode payload = json.readTree(job.payloadJson());
            String title = mailer.title(device.locale(), job.type(), payload);
            Map<String, String> data = new LinkedHashMap<>();
            data.put("alertId", job.alertId().toString());
            data.put("homeId", job.homeId().toString());
            data.put("type", job.type());
            switch (push.send(device.token(), title, job.homeName(), data)) {
                case SENT -> sent = true;
                case INVALID_TOKEN -> pushDevices.delete(device.id());
                case FAILED -> temporary = true;
            }
        }
        if (sent) {
            alerts.deliverySent(job.deliveryId(), attempts, clock.instant());
        } else if (temporary) {
            retryOrFail(job, attempts, "PUSH_ERROR");
        } else {
            alerts.deliveryNotSent(job.deliveryId(), attempts, "NO_PUSH_DEVICE", null);
        }
        return sent;
    }

    private void retryOrFail(DeliveryJob job, int attempts, String error) {
        Instant next = attempts < MAX_ATTEMPTS ? clock.instant().plus(RETRY.get(attempts - 1)) : null;
        alerts.deliveryNotSent(job.deliveryId(), attempts, error, next);
    }

    /** Returns the number of agents examined. */
    @Scheduled(initialDelayString = "PT2M", fixedDelayString = "${shsc.alerts.agent-check-interval:PT1M}")
    public int checkAgents() {
        Instant now = clock.instant();
        Instant cutoff = now.minus(AgentRuntimeService.STALE_WITHIN);
        List<Due> due = tx.execute(status -> jdbc.sql("SELECT tenant_id, agent_id FROM agents_offline_since(:cutoff, :limit)")
                .param("cutoff", Sql.ts(cutoff)).param("limit", BATCH)
                .query((rs, n) -> new Due(Sql.uuid(rs, "tenant_id"), Sql.uuid(rs, "agent_id"))).list());
        for (Due d : due) {
            tenantScope.runAs(d.tenantId(), () -> service.agentOffline(d.tenantId(), d.id(), cutoff, now));
        }
        return due.size();
    }
}
