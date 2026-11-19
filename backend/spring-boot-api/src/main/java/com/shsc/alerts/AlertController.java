package com.shsc.alerts;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.alerts.AlertRepository.InboxItem;
import com.shsc.alerts.AlertRepository.Preference;
import com.shsc.shared.web.ApiException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Alerts of the current user (docs/05-API.md §Alerts): the dashboard inbox, read state and the
 * notification preferences (per alert type and channel).
 */
@RestController
public class AlertController {

    public record AlertResponse(UUID id, UUID homeId, String homeName, UUID deviceId, String type, String severity,
            int occurrences, Instant firstAt, Instant lastAt, Instant resolvedAt, Instant readAt,
            Map<String, Object> payload) {
    }

    public record PreferenceItem(@NotNull String type, @NotNull String channel, boolean enabled,
            @NotNull String minSeverity) {
    }

    public record PreferencesRequest(@NotNull @Size(max = 20) List<@Valid PreferenceItem> items) {
    }

    private final AlertService service;
    private final JsonMapper json;

    public AlertController(AlertService service, JsonMapper json) {
        this.service = service;
        this.json = json;
    }

    @GetMapping("/api/v1/alerts")
    public List<AlertResponse> list(@RequestParam(defaultValue = "false") boolean unread,
            @RequestParam(required = false) Integer limit) {
        return service.inbox(unread, limit).stream().map(this::response).toList();
    }

    @GetMapping("/api/v1/alerts/unread-count")
    public Map<String, Integer> unreadCount() {
        return Map.of("count", service.unreadCount());
    }

    @PostMapping("/api/v1/alerts/{id}/read")
    public ResponseEntity<Void> read(@PathVariable UUID id) {
        service.markRead(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/alerts/read-all")
    public Map<String, Integer> readAll() {
        return Map.of("count", service.markAllRead());
    }

    @GetMapping("/api/v1/notification-preferences")
    public List<PreferenceItem> preferences() {
        return service.preferences().stream().map(AlertController::item).toList();
    }

    @PutMapping("/api/v1/notification-preferences")
    public List<PreferenceItem> savePreferences(@Valid @RequestBody PreferencesRequest request) {
        List<Preference> items = request.items().stream().map(i -> {
            try {
                return new Preference(AlertType.valueOf(i.type()), AlertType.Channel.valueOf(i.channel()),
                        i.enabled(), i.minSeverity());
            } catch (IllegalArgumentException e) {
                throw ApiException.badRequest("INVALID_PREFERENCE", "Unknown alert type or channel.");
            }
        }).toList();
        return service.savePreferences(items).stream().map(AlertController::item).toList();
    }

    private static PreferenceItem item(Preference p) {
        return new PreferenceItem(p.type().name(), p.channel().name(), p.enabled(), p.minSeverity());
    }

    private AlertResponse response(InboxItem i) {
        return new AlertResponse(i.alertId(), i.homeId(), i.homeName(), i.deviceId(), i.type(), i.severity(),
                i.occurrences(), i.firstAt(), i.lastAt(), i.resolvedAt(), i.readAt(),
                json.readValue(i.payloadJson(), new TypeReference<Map<String, Object>>() {
                }));
    }
}
