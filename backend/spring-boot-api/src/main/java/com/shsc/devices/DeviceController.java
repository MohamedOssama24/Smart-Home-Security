package com.shsc.devices;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.devices.DeviceRepository.CategoryChange;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.devices.DeviceRepository.Identification;
import com.shsc.devices.DeviceRepository.IdentificationChange;
import com.shsc.devices.fingerprint.FieldResolver;
import com.shsc.devices.DeviceService.DeviceDetail;
import com.shsc.devices.DeviceService.Services;
import com.shsc.devices.oui.OuiRepository.RegistryStatus;
import com.shsc.devices.oui.OuiSyncService;
import com.shsc.devices.oui.OuiSyncService.SyncResult;
import com.shsc.scans.PortResponse;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Device inventory (docs/05-API.md §Devices) and IEEE registry administration. Detected
 * values come with their confidence and sources; {@code category} is the manual category
 * when set, otherwise the detected one, and {@code suggestedCategory} reports a confident
 * detection that disagrees with the manual choice (never applied automatically).
 */
@RestController
public class DeviceController {

    public record ClassifyRequest(@Size(max = 32) String category) {
    }

    public record IdentificationResponse(String field, String value, String confidence,
            List<Map<String, Object>> sources, boolean conflict, UUID scanId, Instant identifiedAt, String status) {
    }

    public record CategoryChangeResponse(String source, String oldCategory, String newCategory, UUID scanId,
            UUID changedBy, Instant changedAt) {
        static CategoryChangeResponse of(CategoryChange c) {
            return new CategoryChangeResponse(c.source(), c.oldCategory(), c.newCategory(), c.scanId(), c.changedBy(),
                    c.changedAt());
        }
    }

    public record DeviceResponse(UUID id, UUID homeId, String mac, boolean macRandomized, UUID probableSameAs,
            String ip, List<String> addresses, String hostname, String manufacturer, String model, String os,
            String category, String detectedCategory, String detectedCategoryConfidence, String manualCategory,
            Instant manualCategoryAt, String suggestedCategory, String overallConfidence, String rulesetVersion,
            Map<String, Object> classification, Instant firstSeenAt, Instant lastSeenAt, UUID lastScanId,
            List<IdentificationResponse> identifications, List<CategoryChangeResponse> categoryHistory,
            ServicesResponse services, List<InterfaceResponse> interfaces, List<AddressResponse> addressHistory,
            String customName, String displayName, List<IdentityFieldResponse> identity,
            List<IdentificationChangeResponse> identificationHistory) {
    }

    /** One MAC of the device (M19); {@code agentInterface}: interface of the agent that saw it. */
    public record InterfaceResponse(String mac, boolean macRandomized, String vendor, String agentInterface,
            boolean current, Instant firstSeenAt, Instant lastSeenAt) {
    }

    /**
     * One address of the history (M19): {@code current} when seen by the last scan of the device;
     * {@code interfaceId} EUI64 (embeds {@code eui64Mac}) or RANDOM (temporary/privacy IPv6).
     */
    public record AddressResponse(String address, int family, String scope, String interfaceId, String eui64Mac,
            String mac, boolean current, Instant firstSeenAt, Instant lastSeenAt, int timesSeen) {
    }

    public record MergeRequest(@NotNull UUID intoDeviceId) {
    }

    /**
     * One field of the device card (M20): status VERIFIED / PROBABLE / UNKNOWN (no value), the
     * names of the agreeing sources and whether the user confirmed it.
     */
    public record IdentityFieldResponse(String field, String value, String status, String confidence,
            List<String> sources, boolean userConfirmed, boolean conflict) {
    }

    public record IdentificationChangeResponse(String field, String oldValue, String newValue, String oldStatus,
            String newStatus, String origin, UUID scanId, Instant changedAt) {
        static IdentificationChangeResponse of(IdentificationChange c) {
            return new IdentificationChangeResponse(c.field(), c.oldValue(), c.newValue(), c.oldStatus(),
                    c.newStatus(), c.origin(), c.scanId(), c.changedAt());
        }
    }

    /** {"field": "FIRMWARE", "value": "1.2.3"} confirms or corrects a field; value null removes the confirmation. */
    public record ConfirmRequest(@NotNull @Size(max = 32) String field, @Size(max = 255) String value) {
    }

    public record RenameRequest(@Size(max = 100) String name) {
    }

    /** Fields of the card, in display order. */
    static final List<String> CARD_FIELDS = List.of("HOSTNAME", "MANUFACTURER", "MODEL", "PRODUCT_CODE", "FIRMWARE",
            "OS", "DEVICE_TYPE", "CPE");

    public record DismissSameAsRequest(@NotNull UUID otherDeviceId) {
    }

    /** Last port scan of the device: counters, open ports with their service, detected protocols. */
    public record ServicesResponse(UUID scanId, Instant scannedAt, Map<String, Object> summary,
            List<PortResponse> ports, List<ProtocolResponse> protocols) {
    }

    public record ProtocolResponse(String protocol, String confidence, Map<String, Object> details) {
    }

    private final DeviceService service;
    private final OuiSyncService oui;
    private final JsonMapper json;

    public DeviceController(DeviceService service, OuiSyncService oui, JsonMapper json) {
        this.service = service;
        this.oui = oui;
        this.json = json;
    }

    @GetMapping("/api/v1/homes/{homeId}/devices")
    public List<DeviceResponse> list(@PathVariable UUID homeId) {
        return service.list(homeId).stream().map(d -> response(d, null, null, null)).toList();
    }

    @GetMapping("/api/v1/devices/{deviceId}")
    public DeviceResponse get(@PathVariable UUID deviceId) {
        return response(service.detail(deviceId));
    }

    /** {"category": "IP_CAMERA"} sets the manual category, {"category": null} clears it. */
    @PutMapping("/api/v1/devices/{deviceId}/category")
    public DeviceResponse classify(@PathVariable UUID deviceId, @Valid @RequestBody ClassifyRequest request,
            HttpServletRequest http) {
        return response(service.classify(deviceId, request.category(), ClientInfo.from(http)));
    }

    /**
     * The user confirms that this device is the same physical device as {@code intoDeviceId}:
     * it is merged into that one and removed; the response is the merged device (M19).
     */
    @PostMapping("/api/v1/devices/{deviceId}/merge")
    public DeviceResponse merge(@PathVariable UUID deviceId, @Valid @RequestBody MergeRequest request,
            HttpServletRequest http) {
        return response(service.merge(deviceId, request.intoDeviceId(), ClientInfo.from(http)));
    }

    /** The user confirms or corrects a field of the card (M20). */
    @PutMapping("/api/v1/devices/{deviceId}/identity")
    public DeviceResponse confirm(@PathVariable UUID deviceId, @Valid @RequestBody ConfirmRequest request,
            HttpServletRequest http) {
        return response(service.confirm(deviceId, request.field(), request.value(), ClientInfo.from(http)));
    }

    /** {"name": "TV soggiorno"} sets the user's name of the device, {"name": null} clears it (M20). */
    @PutMapping("/api/v1/devices/{deviceId}/name")
    public DeviceResponse rename(@PathVariable UUID deviceId, @Valid @RequestBody RenameRequest request,
            HttpServletRequest http) {
        return response(service.rename(deviceId, request.name(), ClientInfo.from(http)));
    }

    /** The user says the two devices are different: no more "probably the same device" hint (M19). */
    @PostMapping("/api/v1/devices/{deviceId}/same-as/dismiss")
    public DeviceResponse dismissSameAs(@PathVariable UUID deviceId, @Valid @RequestBody DismissSameAsRequest request,
            HttpServletRequest http) {
        return response(service.dismissSameAs(deviceId, request.otherDeviceId(), ClientInfo.from(http)));
    }

    /** IEEE registries loaded (platform administrators). */
    @GetMapping("/api/v1/platform/oui")
    public List<RegistryStatus> ouiStatus() {
        return oui.status();
    }

    /** Downloads and replaces the IEEE registries (platform administrators, never automatic). */
    @PostMapping("/api/v1/platform/oui/sync")
    public SyncResult ouiSync() {
        return oui.sync();
    }

    private DeviceResponse response(DeviceDetail detail) {
        DeviceResponse r = response(detail.device(), detail.identifications(), detail.changes(),
                services(detail.services()));
        UUID lastScan = detail.device().lastScanId();
        List<InterfaceResponse> interfaces = detail.interfaces().stream()
                .map(i -> new InterfaceResponse(i.mac(), i.macRandomized(), i.vendor(), i.agentInterface(),
                        lastScan.equals(i.lastScanId()), i.firstSeenAt(), i.lastSeenAt()))
                .toList();
        List<AddressResponse> addresses = detail.addressHistory().stream().map(a -> {
            Addresses.Info info = Addresses.classify(a.address()).orElse(null);
            return new AddressResponse(a.address(), info == null ? 0 : info.family(),
                    info == null ? null : info.scope().name(),
                    info == null || info.interfaceId() == null ? null : info.interfaceId().name(),
                    info == null ? null : info.eui64Mac(), a.mac(), lastScan.equals(a.lastScanId()), a.firstSeenAt(),
                    a.lastSeenAt(), a.timesSeen());
        }).toList();
        return new DeviceResponse(r.id(), r.homeId(), r.mac(), r.macRandomized(), r.probableSameAs(), r.ip(),
                r.addresses(), r.hostname(), r.manufacturer(), r.model(), r.os(), r.category(), r.detectedCategory(),
                r.detectedCategoryConfidence(), r.manualCategory(), r.manualCategoryAt(), r.suggestedCategory(),
                r.overallConfidence(), r.rulesetVersion(), r.classification(), r.firstSeenAt(), r.lastSeenAt(),
                r.lastScanId(), r.identifications(), r.categoryHistory(), r.services(), interfaces, addresses,
                r.customName(), r.displayName(), identity(r.identifications()),
                detail.identificationHistory().stream().map(IdentificationChangeResponse::of).toList());
    }

    private ServicesResponse services(Services s) {
        if (s == null) {
            return null;
        }
        return new ServicesResponse(s.scan().scanId(), s.scan().observedAt(), map(s.scan().summaryJson()),
                s.ports().stream().map(p -> PortResponse.of(p, json)).toList(),
                s.protocols().stream().map(p -> new ProtocolResponse(p.protocol(), p.confidence(), map(p.detailsJson())))
                        .toList());
    }

    private DeviceResponse response(Device d, List<Identification> ids, List<CategoryChange> changes,
            ServicesResponse services) {
        String category = d.manualCategory() != null ? d.manualCategory() : d.detectedCategory();
        boolean confident = "HIGH".equals(d.detectedConfidence())
                || "MEDIUM".equals(d.detectedConfidence());
        String suggested = d.manualCategory() != null && confident && !"UNKNOWN_DEVICE".equals(d.detectedCategory())
                && !d.detectedCategory().equals(d.manualCategory()) ? d.detectedCategory() : null;
        return new DeviceResponse(d.id(), d.homeId(), d.mac(), d.macRandomized(), d.probableSameAs(), d.currentIp(),
                d.addresses(), d.hostname(), d.manufacturer(), d.model(), d.osName(), category, d.detectedCategory(),
                d.detectedConfidence(), d.manualCategory(), d.manualCategoryAt(), suggested, d.overallConfidence(),
                d.rulesetVersion(), map(d.classificationJson()), d.firstSeenAt(), d.lastSeenAt(), d.lastScanId(),
                ids == null ? null : ids.stream().map(this::identification).toList(),
                changes == null ? null : changes.stream().map(CategoryChangeResponse::of).toList(),
                services, null, null, d.customName(), d.customName() != null ? d.customName() : d.hostname(), null,
                null);
    }

    private IdentificationResponse identification(Identification i) {
        List<Map<String, Object>> sources = json.readValue(i.sourcesJson(),
                new TypeReference<List<Map<String, Object>>>() {
                });
        return new IdentificationResponse(i.field(), i.value(), i.confidence(), sources, i.conflict(), i.scanId(),
                i.identifiedAt(), i.status() == null ? "PROBABLE" : i.status());
    }

    private static List<IdentityFieldResponse> identity(List<IdentificationResponse> ids) {
        Map<String, IdentificationResponse> byField = new java.util.HashMap<>();
        ids.forEach(i -> byField.put(i.field(), i));
        return CARD_FIELDS.stream().map(f -> {
            IdentificationResponse i = byField.get(f);
            if (i == null) {
                return new IdentityFieldResponse(f, null, "UNKNOWN", null, List.of(), false, false);
            }
            List<String> sources = i.sources().stream().filter(s -> Boolean.TRUE.equals(s.get("agrees")))
                    .map(s -> String.valueOf(s.get("source"))).distinct().toList();
            return new IdentityFieldResponse(f, i.value(), i.status(), i.confidence(), sources,
                    sources.contains(FieldResolver.SOURCE_USER), i.conflict());
        }).toList();
    }

    private Map<String, Object> map(String value) {
        return json.readValue(value, new TypeReference<Map<String, Object>>() {
        });
    }
}
