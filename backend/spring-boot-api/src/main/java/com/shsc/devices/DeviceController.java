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
import com.shsc.devices.DeviceService.DeviceDetail;
import com.shsc.devices.DeviceService.Services;
import com.shsc.devices.oui.OuiRepository.RegistryStatus;
import com.shsc.devices.oui.OuiSyncService;
import com.shsc.devices.oui.OuiSyncService.SyncResult;
import com.shsc.scans.PortResponse;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
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
            List<Map<String, Object>> sources, boolean conflict, UUID scanId, Instant identifiedAt) {
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
            ServicesResponse services) {
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
        return response(detail.device(), detail.identifications(), detail.changes(), services(detail.services()));
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
                services);
    }

    private IdentificationResponse identification(Identification i) {
        List<Map<String, Object>> sources = json.readValue(i.sourcesJson(),
                new TypeReference<List<Map<String, Object>>>() {
                });
        return new IdentificationResponse(i.field(), i.value(), i.confidence(), sources, i.conflict(), i.scanId(),
                i.identifiedAt());
    }

    private Map<String, Object> map(String value) {
        return json.readValue(value, new TypeReference<Map<String, Object>>() {
        });
    }
}
