package com.shsc.alerts.push;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.alerts.push.PushDeviceRepository.PushDevice;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Push registrations of the current user's app installations (docs/23-MOBILE-APP.md §3). Any
 * signed-in user may register their own device: the alerts it receives are filtered by the same
 * permissions as the dashboard. The token is bound to the login session of the request.
 */
@RestController
@RequestMapping("/api/v1/push-devices")
public class PushDeviceController {

    public record RegisterRequest(
            @NotBlank @Pattern(regexp = "[A-Za-z0-9:_-]{20,4096}") String token,
            @NotBlank @Pattern(regexp = "ANDROID|IOS") String platform,
            @Pattern(regexp = "it|en") String locale) {
    }

    /** The token is never returned. */
    public record PushDeviceView(UUID id, String platform, String locale, boolean currentSession, Instant createdAt,
            Instant lastSeenAt, boolean pushEnabled) {
    }

    private final PushDeviceRepository devices;
    private final PushGateway gateway;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public PushDeviceController(PushDeviceRepository devices, PushGateway gateway, AccessPolicy access, AuditLog audit,
            Clock clock) {
        this.devices = devices;
        this.gateway = gateway;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public PushDeviceView register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        AuthenticatedUser user = access.currentUser();
        String locale = request.locale() == null ? "it" : request.locale();
        PushDevice device = devices.upsert(user.tenantId(), user.userId(), user.sessionId(), request.platform(),
                request.token(), locale, clock.instant());
        audit.record(AuditEvent.of(AuditAction.PUSH_DEVICE_REGISTERED).tenant(user.tenantId()).user(user.userId())
                .target("PUSH_DEVICE", device.id()).client(ClientInfo.from(http)).build());
        return view(device, user);
    }

    @GetMapping
    @Transactional(readOnly = true)
    public List<PushDeviceView> list() {
        AuthenticatedUser user = access.currentUser();
        return devices.ofUser(user.userId()).stream().map(d -> view(d, user)).toList();
    }

    /** Removes one of the user's own registrations (404 otherwise). */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void remove(@PathVariable UUID id, HttpServletRequest http) {
        AuthenticatedUser user = access.currentUser();
        PushDevice device = devices.find(id).filter(d -> d.userId().equals(user.userId()))
                .orElseThrow(ApiException::notFound);
        devices.delete(device.id());
        audit.record(AuditEvent.of(AuditAction.PUSH_DEVICE_REMOVED).tenant(user.tenantId()).user(user.userId())
                .target("PUSH_DEVICE", device.id()).client(ClientInfo.from(http)).build());
    }

    private PushDeviceView view(PushDevice d, AuthenticatedUser user) {
        return new PushDeviceView(d.id(), d.platform(), d.locale(), d.sessionId().equals(user.sessionId()),
                d.createdAt(), d.lastSeenAt(), gateway.enabled());
    }
}
