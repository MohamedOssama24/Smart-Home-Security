package com.shsc.findings;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.findings.FindingRepository.Finding;
import com.shsc.findings.FindingService.FindingDetail;
import com.shsc.shared.web.ClientInfo;
import com.shsc.vulnintel.VulnerabilityRepository.CveDetail;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Security findings (docs/05-API.md §Findings). Texts are i18n keys with their parameters; the
 * type tells a confirmed vulnerability from a potential risk, a suspicious configuration or an
 * unverified information.
 */
@RestController
public class FindingController {

    public record StatusRequest(@NotBlank @Size(max = 32) String status, @Size(max = 500) String reason) {
    }

    public record DeviceRef(UUID id, String name, String ip, String category) {
    }

    public record FindingResponse(UUID id, UUID homeId, DeviceRef device, String ruleId, int ruleVersion,
            String titleKey, String recommendationKey, Map<String, Object> params, String severity, String type,
            String confidence, String source, String protocol, Integer port, String cveId, String status,
            String statusReason, Instant statusChangedAt, Instant firstDetectedAt, Instant lastDetectedAt,
            Instant resolvedAt, UUID lastScanId) {
    }

    public record EvidenceResponse(UUID scanId, String type, Map<String, Object> data, Instant collectedAt) {
    }

    public record CveResponse(String cveId, String matchQuality, String matchedCpe, String product, String version,
            String severity, BigDecimal cvssScore, String cvssVersion, String description, boolean kev,
            LocalDate kevDateAdded, BigDecimal epssScore, BigDecimal epssPercentile) {
    }

    public record FindingDetailResponse(FindingResponse finding, List<EvidenceResponse> evidence,
            List<CveResponse> vulnerabilities, int matchedCves) {
    }

    public record HomeVulnerabilityResponse(String cveId, String severity, BigDecimal cvssScore, boolean kev,
            BigDecimal epssScore, String matchQuality, String product, String version, DeviceRef device,
            UUID findingId, String findingStatus, String findingType) {
    }

    private final FindingService service;
    private final JsonMapper json;

    public FindingController(FindingService service, JsonMapper json) {
        this.service = service;
        this.json = json;
    }

    @GetMapping("/api/v1/homes/{homeId}/findings")
    public List<FindingResponse> list(@PathVariable UUID homeId, @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity, @RequestParam(required = false) String type) {
        return service.list(homeId, status, severity, type).stream().map(this::response).toList();
    }

    @GetMapping("/api/v1/homes/{homeId}/vulnerabilities")
    public List<HomeVulnerabilityResponse> vulnerabilities(@PathVariable UUID homeId) {
        return service.vulnerabilities(homeId).stream().map(v -> new HomeVulnerabilityResponse(v.cveId(),
                v.severity(), v.cvssScore(), v.kev(), v.epssScore(), v.matchQuality(), v.product(), v.version(),
                new DeviceRef(v.deviceId(), v.deviceName(), v.deviceIp(), null), v.findingId(), v.findingStatus(),
                v.findingType())).toList();
    }

    @GetMapping("/api/v1/findings/{id}")
    public FindingDetailResponse detail(@PathVariable UUID id) {
        return response(service.detail(id));
    }

    @PatchMapping("/api/v1/findings/{id}/status")
    public FindingDetailResponse changeStatus(@PathVariable UUID id, @Valid @RequestBody StatusRequest request,
            HttpServletRequest http) {
        return response(service.changeStatus(id, request.status(), request.reason(), ClientInfo.from(http)));
    }

    private FindingDetailResponse response(FindingDetail d) {
        Map<String, CveDetail> byId = new HashMap<>();
        d.vulnerabilities().forEach(v -> byId.put(v.id(), v));
        List<CveResponse> cves = d.matches().stream().filter(m -> byId.containsKey(m.cveId())).map(m -> {
            CveDetail v = byId.get(m.cveId());
            return new CveResponse(m.cveId(), m.matchQuality(), m.matchedCpe(), m.product(), m.version(),
                    v.severity(), v.cvssScore(), v.cvssVersion(), v.description(), v.kevDateAdded() != null,
                    v.kevDateAdded(), v.epssScore(), v.epssPercentile());
        }).toList();
        return new FindingDetailResponse(response(d.finding()),
                d.evidence().stream().map(e -> new EvidenceResponse(e.scanId(), e.type(), object(e.dataJson()),
                        e.collectedAt())).toList(),
                cves, d.matches().size());
    }

    private FindingResponse response(Finding f) {
        return new FindingResponse(f.id(), f.homeId(),
                new DeviceRef(f.deviceId(), f.deviceName(), f.deviceIp(), f.deviceCategory()), f.ruleId(),
                f.ruleVersion(), f.titleKey(), f.recommendationKey(), object(f.paramsJson()), f.severity(), f.type(),
                f.confidence(), f.source(), f.protocol(), f.port(), f.cveId(), f.status(), f.statusReason(),
                f.statusChangedAt(), f.firstDetectedAt(), f.lastDetectedAt(), f.resolvedAt(), f.lastScanId());
    }

    private Map<String, Object> object(String text) {
        return text == null ? Map.of() : json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }
}
