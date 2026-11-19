package com.shsc.alerts;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.alerts.AlertRepository.AgentInfo;
import com.shsc.alerts.AlertRepository.InboxItem;
import com.shsc.alerts.AlertRepository.NewAlert;
import com.shsc.alerts.AlertRepository.NewDevice;
import com.shsc.alerts.AlertRepository.Preference;
import com.shsc.alerts.AlertRepository.Raised;
import com.shsc.alerts.AlertRepository.Recipient;
import com.shsc.alerts.AlertRepository.SevereFinding;
import com.shsc.alerts.AlertRepository.SnapshotScore;
import com.shsc.alerts.AlertType.Channel;
import com.shsc.alerts.push.PushDeviceRepository;
import com.shsc.alerts.push.PushGateway;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.RoleAssignment;
import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.shared.web.ApiException;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Alerts (docs/22-ALERTS-REPORTS.md): raised in the transaction of the event that causes them
 * (scan completed or failed, triage, agent offline), deduplicated by key, delivered to the users
 * who may see the home's data, according to their preferences. E-mails are sent later by
 * {@link AlertJobs}; a repeated occurrence of an unresolved alert sends nothing new.
 */
@Service
public class AlertService {

    private static final Logger LOG = LoggerFactory.getLogger(AlertService.class);
    /** Score drop (points) that raises SCORE_DROPPED; a worse risk level raises it too. */
    public static final int SCORE_DROP_POINTS = 10;
    /** Above this many devices first seen by one scan, a single summary alert is raised. */
    public static final int MAX_DEVICE_ALERTS = 10;
    private static final int MAX_INBOX = 200;
    private static final List<String> LEVELS = List.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    public record Preferences(List<Preference> items) {
    }

    private final AlertRepository alerts;
    private final RoleAssignmentRepository assignments;
    private final AccessPolicy access;
    private final PushGateway push;
    private final PushDeviceRepository pushDevices;
    private final JsonMapper json;
    private final Clock clock;

    public AlertService(AlertRepository alerts, RoleAssignmentRepository assignments, AccessPolicy access,
            PushGateway push, PushDeviceRepository pushDevices, JsonMapper json, Clock clock) {
        this.alerts = alerts;
        this.assignments = assignments;
        this.access = access;
        this.push = push;
        this.pushDevices = pushDevices;
        this.json = json;
        this.clock = clock;
    }

    // --- events (called inside the transaction of the change) --------------------------------

    /** After the security analysis and the risk snapshot of a completed scan. */
    public void onScanCompleted(Scan scan, UUID snapshotId, Instant now) {
        alerts.resolve(scanFailedKey(scan.homeId()), now);
        for (SevereFinding f : alerts.severeFindingsSeen(scan.homeId(), scan.id())) {
            raise(scan.tenantId(), scan.homeId(), f.deviceId(), AlertType.NEW_FINDING, severity(f.severity()),
                    findingKey(f.id()), finding(f, scan.id()), now);
        }
        for (SevereFinding f : alerts.resolvedAt(scan.homeId(), now)) {
            // only findings that had raised an alert: resolving a LOW finding is not news
            if (alerts.resolve(findingKey(f.id()), now)) {
                raise(scan.tenantId(), scan.homeId(), f.deviceId(), AlertType.FINDING_RESOLVED, "INFO",
                        "resolved:" + f.id() + ":" + scan.id(), finding(f, scan.id()), now);
            }
        }
        if (snapshotId != null) {
            alerts.snapshotScore(snapshotId).ifPresent(s -> scoreChanged(scan, s, now));
        }
        if (alerts.completedBefore(scan.homeId(), scan.id())) {
            newDevices(scan, alerts.devicesFirstSeen(scan.homeId(), scan.id()), now);
        }
    }

    private void scoreChanged(Scan scan, SnapshotScore s, Instant now) {
        if (s.score() == null || s.scoreChange() == null) {
            return;
        }
        String key = "score-drop:" + scan.homeId();
        boolean worseLevel = LEVELS.indexOf(s.riskLevel()) > LEVELS.indexOf(s.previousLevel())
                && s.previousLevel() != null;
        if (s.scoreChange() <= -SCORE_DROP_POINTS || (s.scoreChange() < 0 && worseLevel)) {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("scanId", scan.id().toString());
            payload.put("score", s.score());
            payload.put("previousScore", s.previousScore());
            payload.put("scoreChange", s.scoreChange());
            payload.put("riskLevel", s.riskLevel());
            payload.put("previousLevel", s.previousLevel());
            String severity = switch (s.riskLevel()) {
                case "CRITICAL" -> "CRITICAL";
                case "HIGH" -> "HIGH";
                default -> "MEDIUM";
            };
            raise(scan.tenantId(), scan.homeId(), null, AlertType.SCORE_DROPPED, severity, key, payload, now);
        } else if (s.scoreChange() > 0) {
            alerts.resolve(key, now);
        }
    }

    private void newDevices(Scan scan, List<NewDevice> devices, Instant now) {
        if (devices.isEmpty()) {
            return;
        }
        if (devices.size() <= MAX_DEVICE_ALERTS) {
            for (NewDevice d : devices) {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("scanId", scan.id().toString());
                payload.put("count", 1);
                payload.put("devices", List.of(device(d)));
                raise(scan.tenantId(), scan.homeId(), d.id(), AlertType.NEW_DEVICE, "LOW", "device:" + d.id(),
                        payload, now);
            }
            return;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("scanId", scan.id().toString());
        payload.put("count", devices.size());
        payload.put("devices", devices.stream().limit(MAX_DEVICE_ALERTS).map(AlertService::device).toList());
        raise(scan.tenantId(), scan.homeId(), null, AlertType.NEW_DEVICE, "LOW", "devices:" + scan.id(), payload,
                now);
    }

    /** A scan ended FAILED: repeated failures of the same home are one alert with its occurrences. */
    public void onScanFailed(Scan scan, String reason, Instant now) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("scanId", scan.id().toString());
        payload.put("profile", scan.profile());
        payload.put("reason", reason);
        raise(scan.tenantId(), scan.homeId(), null, AlertType.SCAN_FAILED, "MEDIUM", scanFailedKey(scan.homeId()),
                payload, now);
    }

    /** A finding marked false positive / accepted risk no longer needs its alert. */
    public void onFindingTriaged(UUID findingId, String status, Instant now) {
        if ("FALSE_POSITIVE".equals(status) || "ACCEPTED_RISK".equals(status)) {
            alerts.resolve(findingKey(findingId), now);
        }
    }

    /** The agent is back: its offline alert is resolved. */
    public void onHeartbeat(UUID agentId, Instant now) {
        alerts.resolve(agentOfflineKey(agentId), now);
    }

    /** Called by {@link AlertJobs} in the agent's tenant for an agent without heartbeat. */
    @Transactional
    public void agentOffline(UUID tenantId, UUID agentId, Instant cutoff, Instant now) {
        AgentInfo agent = alerts.agent(agentId).orElse(null);
        if (agent == null || !"ACTIVE".equals(agent.status()) || agent.lastHeartbeatAt() == null
                || !agent.lastHeartbeatAt().isBefore(cutoff) || alerts.findOpen(agentOfflineKey(agentId)).isPresent()) {
            return; // back online, revoked or already alerted meanwhile
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("agentId", agentId.toString());
        payload.put("agentName", agent.name());
        payload.put("lastHeartbeatAt", agent.lastHeartbeatAt().toString());
        raise(tenantId, agent.homeId(), null, AlertType.AGENT_OFFLINE, "MEDIUM", agentOfflineKey(agentId), payload,
                now);
    }

    /** Raises (or repeats) the alert; on creation decides the deliveries of every recipient. */
    Raised raise(UUID tenantId, UUID homeId, UUID deviceId, AlertType type, String severity, String key,
            Map<String, Object> payload, Instant now) {
        Raised raised = alerts.raise(new NewAlert(tenantId, homeId, deviceId, type, severity, key,
                json.writeValueAsString(payload), now));
        if (!raised.created()) {
            return raised; // deduplicated: one more occurrence, nothing new is sent
        }
        Map<UUID, List<RoleAssignment>> byUser = assignments.all().stream().collect(Collectors.groupingBy(
                a -> a.userId(), Collectors.mapping(a -> a.assignment(), Collectors.toList())));
        int deliveries = 0;
        for (Recipient r : alerts.recipients()) {
            List<RoleAssignment> roles = byUser.get(r.id());
            if (roles == null || !access.hasOnHome(new AuthenticatedUser(r.id(), tenantId, null, r.email(),
                    r.displayName(), roles), type.permission(), homeId)) {
                continue;
            }
            Map<Channel, Preference> prefs = effective(alerts.preferences(r.id())).get(type);
            for (Channel channel : Channel.values()) {
                Preference p = prefs.get(channel);
                if (channel == Channel.PUSH && (!push.enabled() || !pushDevices.hasActive(r.id(), now))) {
                    continue; // FCM not configured or no app signed in for this user
                }
                if (p.enabled() && AlertType.rank(severity) >= AlertType.rank(p.minSeverity())) {
                    alerts.insertDelivery(tenantId, raised.id(), r.id(), channel, now);
                    deliveries++;
                }
            }
        }
        LOG.info("Alert {} {} for home {}: {} deliveries", type, severity, homeId, deliveries);
        return raised;
    }

    // --- dashboard ----------------------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<InboxItem> inbox(boolean unreadOnly, Integer limit) {
        int n = limit == null ? 50 : limit;
        if (n < 1 || n > MAX_INBOX) {
            throw ApiException.badRequest("INVALID_LIMIT", "limit must be between 1 and " + MAX_INBOX + ".");
        }
        AuthenticatedUser user = access.currentUser();
        return visible(user, alerts.inbox(user.userId(), unreadOnly, MAX_INBOX)).stream().limit(n).toList();
    }

    @Transactional(readOnly = true)
    public int unreadCount() {
        AuthenticatedUser user = access.currentUser();
        return visible(user, alerts.inbox(user.userId(), true, MAX_INBOX)).size();
    }

    /** Marks one alert read (404 if it is not in the user's inbox). */
    @Transactional
    public void markRead(UUID alertId) {
        AuthenticatedUser user = access.currentUser();
        InboxItem item = alerts.inboxItem(user.userId(), alertId).filter(i -> canSee(user, i))
                .orElseThrow(ApiException::notFound);
        alerts.markRead(user.userId(), List.of(item.alertId()), clock.instant());
    }

    @Transactional
    public int markAllRead() {
        AuthenticatedUser user = access.currentUser();
        List<UUID> ids = visible(user, alerts.inbox(user.userId(), true, MAX_INBOX)).stream()
                .map(InboxItem::alertId).toList();
        alerts.markRead(user.userId(), ids, clock.instant());
        return ids.size();
    }

    /** Permissions are checked again when reading: a role revoked meanwhile hides the alert. */
    private List<InboxItem> visible(AuthenticatedUser user, List<InboxItem> items) {
        return items.stream().filter(i -> canSee(user, i)).toList();
    }

    private boolean canSee(AuthenticatedUser user, InboxItem i) {
        return access.hasOnHome(user, AlertType.valueOf(i.type()).permission(), i.homeId());
    }

    @Transactional(readOnly = true)
    public List<Preference> preferences() {
        AuthenticatedUser user = access.currentUser();
        return flatten(effective(alerts.preferences(user.userId())));
    }

    @Transactional
    public List<Preference> savePreferences(List<Preference> items) {
        AuthenticatedUser user = access.currentUser();
        Instant now = clock.instant();
        for (Preference p : items) {
            if (p.type() == null || p.channel() == null || AlertType.rank(p.minSeverity()) < 0) {
                throw ApiException.badRequest("INVALID_PREFERENCE",
                        "type, channel and minSeverity (INFO, LOW, MEDIUM, HIGH, CRITICAL) are required.");
            }
        }
        items.forEach(p -> alerts.savePreference(user.tenantId(), user.userId(), p, now));
        return flatten(effective(alerts.preferences(user.userId())));
    }

    // --- helpers ------------------------------------------------------------------------------

    /** Saved preferences over the defaults, for every type and channel. */
    static Map<AlertType, Map<Channel, Preference>> effective(List<Preference> saved) {
        Map<AlertType, Map<Channel, Preference>> out = new EnumMap<>(AlertType.class);
        for (AlertType t : AlertType.values()) {
            Map<Channel, Preference> channels = new EnumMap<>(Channel.class);
            for (Channel c : Channel.values()) {
                channels.put(c, new Preference(t, c, true, AlertType.defaultMinSeverity(c)));
            }
            out.put(t, channels);
        }
        saved.forEach(p -> out.get(p.type()).put(p.channel(), p));
        return out;
    }

    private static List<Preference> flatten(Map<AlertType, Map<Channel, Preference>> prefs) {
        List<Preference> out = new ArrayList<>();
        prefs.values().forEach(m -> out.addAll(m.values()));
        return out;
    }

    private Map<String, Object> finding(SevereFinding f, UUID scanId) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("scanId", scanId.toString());
        payload.put("findingId", f.id().toString());
        payload.put("ruleId", f.ruleId());
        payload.put("titleKey", f.titleKey());
        payload.put("params", f.paramsJson() == null ? Map.of()
                : json.readValue(f.paramsJson(), new TypeReference<Map<String, Object>>() {
                }));
        payload.put("findingSeverity", f.severity());
        payload.put("findingType", f.type());
        payload.put("deviceName", f.deviceName());
        payload.put("deviceIp", f.deviceIp());
        return payload;
    }

    private static Map<String, Object> device(NewDevice d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", d.id().toString());
        m.put("name", d.name());
        m.put("ip", d.ip());
        return m;
    }

    /** Finding severities use INFORMATIONAL, alerts INFO. */
    static String severity(String findingSeverity) {
        return "INFORMATIONAL".equals(findingSeverity) ? "INFO" : findingSeverity;
    }

    static String findingKey(UUID findingId) {
        return "finding:" + findingId;
    }

    static String scanFailedKey(UUID homeId) {
        return "scan-failed:" + homeId;
    }

    static String agentOfflineKey(UUID agentId) {
        return "agent-offline:" + agentId;
    }
}
