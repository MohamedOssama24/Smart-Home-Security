package com.shsc.scans;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.scans.ScanQueryService.ScanDetail;
import com.shsc.scans.ScanRepository.Observation;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.ScanEvent;
import com.shsc.scans.ScanRepository.Target;
import com.shsc.scans.ScanRequestService.Profile;
import com.shsc.scans.ScanRequestService.ScanRequestCommand;
import com.shsc.scans.ScanRequestService.ScanRequestResult;
import com.shsc.scans.ScanRequestService.Trigger;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Manual scans for users (docs/05-API.md §Scans). {@code POST /homes/{homeId}/scans} is the
 * only way to start a scan: there is no automatic or scheduled scan in the MVP.
 */
@RestController
public class ScanController {

    public record CreateScanRequest(@NotBlank @Size(max = 20) String profile) {
    }

    public record Progress(String phase, Integer percent) {
    }

    public record TargetResponse(UUID networkId, String cidr) {
        static TargetResponse of(Target t) {
            return new TargetResponse(t.networkId(), t.cidr());
        }
    }

    public record EventResponse(String fromStatus, String toStatus, String actorType, UUID actorId, String reason,
            Instant at) {
        static EventResponse of(ScanEvent e) {
            return new EventResponse(e.fromStatus(), e.toStatus(), e.actorType().name(), e.actorId(), e.reason(),
                    e.at());
        }
    }

    public record ScanResponse(UUID id, UUID homeId, UUID agentId, String trigger, String profile, String status,
            UUID requestedBy, Instant requestedAt, Instant queuedAt, Instant startedAt, Instant completedAt,
            Instant cancelRequestedAt, Progress progress, int devicesDiscovered, int outOfScopeDropped,
            List<String> warnings, String failureReason, List<TargetResponse> targets, List<EventResponse> events) {
    }

    /**
     * A host seen by the scan: its addresses are grouped by MAC address when one is known (IPv4
     * and IPv6 addresses of the same interface), otherwise per address. This is a grouping hint,
     * not an inventory (M8). hostname is the most reliable name found; evidence lists what each
     * method observed, self-declared data being marked as such in its details.
     */
    public record DeviceResponse(String ip, String mac, List<String> methods, String iface, Instant observedAt,
            List<String> addresses, String hostname, List<HostnameResponse> hostnames, List<EvidenceResponse> evidence) {
    }

    public record HostnameResponse(String name, String method) {
    }

    public record EvidenceResponse(String method, String ip, Map<String, Object> details, Instant observedAt) {
    }

    /** Name sources, most reliable first (the router's own table before self-declared names). */
    private static final List<String> NAME_ORDER = List.of("TR064", "MDNS", "NETBIOS", "SNMP", "RDNS");

    private final ScanRequestService requests;
    private final ScanQueryService queries;
    private final JsonMapper json;

    public ScanController(ScanRequestService requests, ScanQueryService queries, JsonMapper json) {
        this.requests = requests;
        this.queries = queries;
        this.json = json;
    }

    /** 202 with the queued scan; 200 with the existing one when the Idempotency-Key was already used. */
    @PostMapping("/api/v1/homes/{homeId}/scans")
    public ResponseEntity<ScanResponse> create(@PathVariable UUID homeId, @Valid @RequestBody CreateScanRequest request,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
            HttpServletRequest http) {
        if (idempotencyKey != null && !idempotencyKey.matches("[A-Za-z0-9_-]{8,64}")) {
            throw ApiException.badRequest("INVALID_IDEMPOTENCY_KEY",
                    "The Idempotency-Key must be 8-64 characters among letters, digits, '-' and '_'.");
        }
        ScanRequestResult result = requests.request(new ScanRequestCommand(homeId, profile(request.profile()),
                Trigger.MANUAL, idempotencyKey, ClientInfo.from(http)));
        return ResponseEntity.status(result.created() ? HttpStatus.ACCEPTED : HttpStatus.OK)
                .body(response(result.scan(), null, null));
    }

    @GetMapping("/api/v1/homes/{homeId}/scans")
    public List<ScanResponse> history(@PathVariable UUID homeId) {
        return queries.history(homeId).stream().map(s -> response(s, null, null)).toList();
    }

    @GetMapping("/api/v1/scans/{scanId}")
    public ScanResponse get(@PathVariable UUID scanId) {
        ScanDetail detail = queries.detail(scanId);
        return response(detail.scan(), detail.targets(), detail.events());
    }

    @PostMapping("/api/v1/scans/{scanId}/cancel")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ScanResponse cancel(@PathVariable UUID scanId, HttpServletRequest http) {
        return response(requests.cancel(scanId, ClientInfo.from(http)), null, null);
    }

    /** Open ports and services found by the scan (QUICK and STANDARD profiles). */
    @GetMapping("/api/v1/scans/{scanId}/ports")
    public List<PortResponse> ports(@PathVariable UUID scanId) {
        return queries.ports(scanId).stream().map(p -> PortResponse.of(p, json)).toList();
    }

    /** Integrations seen by the scan: today only Home Assistant (null when not configured on the agent). */
    @GetMapping("/api/v1/scans/{scanId}/integrations")
    public IntegrationsResponse integrations(@PathVariable UUID scanId) {
        return new IntegrationsResponse(queries.homeAssistant(scanId).map(IntegrationsResponse.HomeAssistant::of).orElse(null));
    }

    /** Hosts observed by the scan, grouped by MAC address when known, otherwise per address. */
    @GetMapping("/api/v1/scans/{scanId}/devices")
    public List<DeviceResponse> devices(@PathVariable UUID scanId) {
        List<Observation> all = queries.observations(scanId);
        Map<String, String> macOf = new LinkedHashMap<>();
        for (Observation o : all) {
            if (o.mac() != null) {
                macOf.putIfAbsent(o.ip(), o.mac());
            }
        }
        Map<String, List<Observation>> groups = new LinkedHashMap<>();
        for (Observation o : all) {
            String mac = macOf.get(o.ip());
            groups.computeIfAbsent(mac != null ? "mac:" + mac : "ip:" + o.ip(), k -> new ArrayList<>()).add(o);
        }
        return groups.values().stream().map(this::device).toList();
    }

    private DeviceResponse device(List<Observation> list) {
        List<String> addresses = list.stream().map(Observation::ip).distinct()
                .sorted(Comparator.comparing((String ip) -> ip.contains(":")).thenComparing(ip -> ip)).toList();
        String mac = list.stream().map(Observation::mac).filter(m -> m != null).findFirst().orElse(null);
        String iface = list.stream().map(Observation::iface).filter(i -> i != null).findFirst().orElse(null);
        Instant last = list.stream().map(Observation::observedAt).max(Instant::compareTo).orElseThrow();
        List<String> methods = List.copyOf(new TreeSet<>(list.stream().map(Observation::method).toList()));
        Map<String, HostnameResponse> names = new LinkedHashMap<>();
        list.stream().filter(o -> o.hostname() != null && NAME_ORDER.contains(o.method()))
                .sorted(Comparator.comparingInt(o -> NAME_ORDER.indexOf(o.method())))
                .forEach(o -> names.putIfAbsent(o.hostname().toLowerCase(Locale.ROOT),
                        new HostnameResponse(o.hostname(), o.method())));
        List<HostnameResponse> hostnames = List.copyOf(names.values());
        List<EvidenceResponse> evidence = list.stream()
                .map(o -> new EvidenceResponse(o.method(), o.ip(), o.details() == null ? null
                        : json.readValue(o.details(), new TypeReference<Map<String, Object>>() {
                        }), o.observedAt()))
                .toList();
        return new DeviceResponse(addresses.get(0), mac, methods, iface, last, addresses,
                hostnames.isEmpty() ? null : hostnames.get(0).name(), hostnames, evidence);
    }

    private static Profile profile(String value) {
        try {
            return Profile.valueOf(value.trim());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("PROFILE_NOT_AVAILABLE",
                    "Available profiles: DISCOVERY, QUICK, STANDARD.");
        }
    }

    private ScanResponse response(Scan s, List<Target> targets, List<ScanEvent> events) {
        Progress progress = s.progressJson() == null ? null : json.readValue(s.progressJson(), Progress.class);
        List<String> warnings = json.readValue(s.warningsJson(), new TypeReference<List<String>>() {
        });
        return new ScanResponse(s.id(), s.homeId(), s.agentId(), s.trigger(), s.profile(), s.status().name(),
                s.requestedBy(), s.requestedAt(), s.queuedAt(), s.startedAt(), s.completedAt(),
                s.cancelRequestedAt(), progress, s.devicesDiscovered(), s.outOfScopeDropped(), warnings,
                s.failureReason(), targets == null ? null : targets.stream().map(TargetResponse::of).toList(),
                events == null ? null : events.stream().map(EventResponse::of).toList());
    }
}
