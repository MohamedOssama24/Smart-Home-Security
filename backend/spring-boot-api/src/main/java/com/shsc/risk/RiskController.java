package com.shsc.risk;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.risk.RiskRepository.Snapshot;
import com.shsc.risk.RiskRepository.Summary;
import com.shsc.risk.RiskService.Current;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Security score of a home (docs/05-API.md §Risk): the current snapshot with its explanation and
 * the history. current is the latest snapshot (its score is null after a DISCOVERY scan);
 * lastScored is the latest snapshot that has a score.
 */
@RestController
public class RiskController {

    public record SnapshotResponse(UUID id, UUID homeId, UUID scanId, String scanProfile, String trigger,
            Integer score, String riskLevel, String rating, String notComputedReason, BigDecimal coverage,
            Map<String, Object> coverageDetail, boolean provisional, Map<String, Object> breakdown,
            List<Map<String, Object>> topDevices, Map<String, Object> delta, Instant computedAt,
            String engineVersion) {
    }

    public record RiskResponse(SnapshotResponse current, SnapshotResponse lastScored) {
    }

    private final RiskService service;
    private final JsonMapper json;

    public RiskController(RiskService service, JsonMapper json) {
        this.service = service;
        this.json = json;
    }

    @GetMapping("/api/v1/homes/{homeId}/risk")
    public RiskResponse current(@PathVariable UUID homeId) {
        Current c = service.current(homeId);
        return new RiskResponse(response(c.current()), response(c.lastScored()));
    }

    @GetMapping("/api/v1/homes/{homeId}/risk/history")
    public List<Summary> history(@PathVariable UUID homeId, @RequestParam(required = false) Integer limit) {
        return service.history(homeId, limit);
    }

    private SnapshotResponse response(Snapshot s) {
        if (s == null) {
            return null;
        }
        return new SnapshotResponse(s.id(), s.homeId(), s.scanId(), s.scanProfile(), s.trigger(), s.score(),
                s.riskLevel(), s.rating(), s.notComputedReason(), s.coverage(), object(s.coverageDetailJson()),
                s.provisional(), object(s.breakdownJson()),
                json.readValue(s.topDevicesJson(), new TypeReference<List<Map<String, Object>>>() {
                }), s.deltaJson() == null ? null : object(s.deltaJson()), s.computedAt(), s.engineVersion());
    }

    private Map<String, Object> object(String text) {
        return json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }
}
