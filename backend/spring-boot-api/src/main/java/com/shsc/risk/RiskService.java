package com.shsc.risk;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.devices.DeviceRepository;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.findings.FindingRepository;
import com.shsc.findings.FindingRepository.DeviceObservation;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.Permissions;
import com.shsc.risk.RiskEngine.Coverage;
import com.shsc.risk.RiskEngine.CoverageInput;
import com.shsc.risk.RiskEngine.Deduction;
import com.shsc.risk.RiskEngine.DeviceInput;
import com.shsc.risk.RiskEngine.DeviceTotal;
import com.shsc.risk.RiskEngine.Excluded;
import com.shsc.risk.RiskEngine.FindingInput;
import com.shsc.risk.RiskEngine.Result;
import com.shsc.risk.RiskRepository.NewSnapshot;
import com.shsc.risk.RiskRepository.OpenFinding;
import com.shsc.risk.RiskRepository.Snapshot;
import com.shsc.risk.RiskRepository.Summary;
import com.shsc.scans.ScanRepository;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.shared.web.ApiException;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Risk snapshots of a home (docs/20-RISK-ENGINE.md): computed at the completion of a scan, after
 * the security analysis and in the same transaction, and again when a triage changes which
 * findings count. Each snapshot keeps its breakdown and the delta from the previous computed one;
 * snapshots are never rewritten.
 */
@Service
public class RiskService {

    private static final Logger LOG = LoggerFactory.getLogger(RiskService.class);
    public static final String TRIGGER_SCAN = "SCAN";
    public static final String TRIGGER_TRIAGE = "TRIAGE";
    private static final int MAX_DEDUCTIONS = 100;
    private static final int MAX_COUNTED_IDS = 1000;
    private static final int MAX_DEVICES = 100;
    private static final int MAX_EXCLUDED = 30;
    private static final int TOP_DEVICES = 5;
    private static final int MAX_DELTA_ITEMS = 20;
    private static final int MAX_BREAKDOWN_BYTES = 250_000;
    private static final int MAX_DELTA_BYTES = 60_000;
    private static final int MAX_HISTORY = 100;

    public record Current(Snapshot current, Snapshot lastScored) {
    }

    private final RiskRepository risk;
    private final ScanRepository scans;
    private final DeviceRepository devices;
    private final FindingRepository findings;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final JsonMapper json;

    public RiskService(RiskRepository risk, ScanRepository scans, DeviceRepository devices, FindingRepository findings,
            HomeRepository homes, AccessPolicy access, JsonMapper json) {
        this.risk = risk;
        this.scans = scans;
        this.devices = devices;
        this.findings = findings;
        this.homes = homes;
        this.access = access;
        this.json = json;
    }

    // --- reading ------------------------------------------------------------------------------

    @Transactional(readOnly = true)
    public Current current(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, homeId);
        Optional<Snapshot> latest = risk.latest(homeId);
        Snapshot scored = latest.filter(s -> s.score() != null).or(() -> risk.latestScored(homeId)).orElse(null);
        return new Current(latest.orElse(null), scored);
    }

    @Transactional(readOnly = true)
    public List<Summary> history(UUID homeId, Integer limit) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, homeId);
        int n = limit == null ? 30 : limit;
        if (n < 1 || n > MAX_HISTORY) {
            throw ApiException.badRequest("INVALID_LIMIT", "limit must be between 1 and " + MAX_HISTORY + ".");
        }
        return risk.history(homeId, n);
    }

    // --- computing ----------------------------------------------------------------------------

    /** At the completion of a scan, after the security analysis (same transaction). */
    public UUID computeForScan(Scan completed, Instant now) {
        Scan scan = scans.find(completed.id()).orElse(completed); // final warnings
        List<Device> homeDevices = devices.forHome(scan.homeId());
        Set<UUID> seen = new HashSet<>();
        List<Device> newDevices = new ArrayList<>();
        for (Device d : homeDevices) {
            if (scan.id().equals(d.lastScanId())) {
                seen.add(d.id());
            }
            if (scan.id().equals(d.firstScanId())) {
                newDevices.add(d);
            }
        }
        Set<UUID> analyzed = new HashSet<>();
        boolean router = false;
        for (DeviceObservation o : findings.observations(scan.id())) {
            if ("TR064".equals(o.method()) || "SNMP".equals(o.method())) {
                router = true; // the owner's router integration answered
            }
            if ("PORTSCAN".equals(o.method()) && o.deviceId() != null && seen.contains(o.deviceId())
                    && !Boolean.TRUE.equals(parse(o.detailsJson()).get("paused"))) {
                analyzed.add(o.deviceId());
            }
        }
        Coverage coverage = RiskEngine.coverage(new CoverageInput(scan.profile(), seen.size(), analyzed.size(),
                warnings(scan.warningsJson()), router));
        boolean portData = !"DISCOVERY".equals(scan.profile());
        return save(scan.tenantId(), scan.homeId(), scan.id(), TRIGGER_SCAN, coverage, portData, homeDevices,
                newDevices, now);
    }

    /**
     * After a triage that changes which findings count (false positive, accepted risk, reopened):
     * same scan and coverage as the last snapshot. Nothing when the home has no computed score yet.
     */
    public void recomputeAfterTriage(UUID homeId, Instant now) {
        Optional<Snapshot> latest = risk.latest(homeId);
        if (latest.isEmpty() || latest.get().score() == null) {
            return;
        }
        Snapshot s = latest.get();
        Coverage coverage = new Coverage(s.coverage().doubleValue(), parse(s.coverageDetailJson()));
        save(s.tenantId(), homeId, s.scanId(), TRIGGER_TRIAGE, coverage, true, devices.forHome(homeId), List.of(),
                now);
    }

    private UUID save(UUID tenantId, UUID homeId, UUID scanId, String trigger, Coverage coverage, boolean portData,
            List<Device> homeDevices, List<Device> newDevices, Instant now) {
        Map<UUID, DeviceInput> deviceInputs = new LinkedHashMap<>();
        for (Device d : homeDevices) {
            deviceInputs.put(d.id(), new DeviceInput(d.id(), name(d), d.currentIp(),
                    d.manualCategory() != null ? d.manualCategory() : d.detectedCategory()));
        }
        List<FindingInput> inputs = new ArrayList<>();
        for (OpenFinding f : risk.openFindings(homeId)) {
            inputs.add(new FindingInput(f.id(), f.deviceId(), f.ruleId(), f.titleKey(), parse(f.paramsJson()),
                    f.severity(), f.type(), f.confidence(), f.status(), f.cveId(), f.kev()));
        }
        Result result = RiskEngine.evaluate(inputs, deviceInputs, coverage, portData);
        Optional<Snapshot> previous = risk.latestScored(homeId);
        String delta = result.score() == null || previous.isEmpty() ? null
                : bounded(params -> delta(result, previous.get(), newDevices, params), MAX_DELTA_BYTES);
        UUID id = risk.insert(new NewSnapshot(tenantId, homeId, scanId, trigger, result.score(), result.riskLevel(),
                result.rating(), result.notComputedReason(),
                BigDecimal.valueOf(coverage.value()).setScale(3, RoundingMode.HALF_UP),
                json.writeValueAsString(coverage.detail()), result.provisional(),
                bounded(params -> breakdown(result, params), MAX_BREAKDOWN_BYTES),
                json.writeValueAsString(topDevices(result)), delta, now, RiskEngine.ENGINE_VERSION));
        LOG.info("Risk of home {} ({}): score {}, coverage {}, provisional {}", homeId, trigger, result.score(),
                coverage.value(), result.provisional());
        return id;
    }

    // --- JSON documents -----------------------------------------------------------------------

    private Map<String, Object> breakdown(Result r, boolean params) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("engineVersion", RiskEngine.ENGINE_VERSION);
        out.put("totalDeduction", r.totalDeduction());
        out.put("uncappedScore", r.uncappedScore());
        out.put("deviceCap", RiskEngine.DEVICE_CAP);
        if (r.provisional() && r.score() != null) {
            out.put("provisionalCap", RiskEngine.PROVISIONAL_CAP);
        }
        out.put("deductionsCount", r.deductions().size());
        out.put("deductions", r.deductions().stream().limit(MAX_DEDUCTIONS).map(d -> deduction(d, params)).toList());
        out.put("countedFindingIds", r.deductions().stream().limit(MAX_COUNTED_IDS)
                .map(d -> d.findingId().toString()).toList());
        out.put("devices", r.devices().stream().limit(MAX_DEVICES).map(RiskService::device).toList());
        out.put("excludedCount", r.excluded().size());
        out.put("excluded", r.excluded().stream().limit(MAX_EXCLUDED).map(e -> excluded(e, params)).toList());
        out.put("notScored", r.notScored());
        return out;
    }

    private static Map<String, Object> deduction(Deduction d, boolean params) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("findingId", d.findingId().toString());
        m.put("deviceId", d.deviceId().toString());
        m.put("ruleId", d.ruleId());
        m.put("titleKey", d.titleKey());
        m.put("params", params ? d.params() : Map.of());
        m.put("severity", d.severity());
        m.put("type", d.type());
        m.put("confidence", d.confidence());
        m.put("status", d.status());
        Map<String, Object> factors = new LinkedHashMap<>();
        factors.put("base", d.base());
        factors.put("type", d.typeFactor());
        factors.put("confidence", d.confidenceFactor());
        factors.put("criticality", d.criticality());
        factors.put("exposure", d.exposure());
        factors.put("kev", d.kev());
        m.put("factors", factors);
        m.put("value", d.value());
        return m;
    }

    private static Map<String, Object> device(DeviceTotal t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("deviceId", t.deviceId().toString());
        m.put("name", t.name());
        m.put("ip", t.ip());
        m.put("category", t.category());
        m.put("criticality", t.criticality());
        m.put("exposed", t.exposed());
        m.put("raw", t.raw());
        m.put("applied", t.applied());
        m.put("capped", t.capped());
        m.put("findings", t.findings());
        return m;
    }

    private static Map<String, Object> excluded(Excluded e, boolean params) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("findingId", e.findingId().toString());
        m.put("deviceId", e.deviceId() == null ? null : e.deviceId().toString());
        m.put("titleKey", e.titleKey());
        m.put("params", params ? e.params() : Map.of());
        m.put("severity", e.severity());
        m.put("status", e.status());
        return m;
    }

    private static List<Map<String, Object>> topDevices(Result r) {
        return r.devices().stream().filter(t -> t.applied() > 0).limit(TOP_DEVICES).map(RiskService::device)
                .toList();
    }

    /** Change from the previous computed snapshot and its reasons. */
    private Map<String, Object> delta(Result r, Snapshot previous, List<Device> newDevices, boolean params) {
        JsonNode before = json.readTree(previous.breakdownJson());
        Set<String> previousIds = new HashSet<>();
        before.path("countedFindingIds").forEach(n -> previousIds.add(n.asString()));
        Map<String, JsonNode> previousDeductions = new LinkedHashMap<>();
        before.path("deductions").forEach(n -> previousDeductions.put(n.path("findingId").asString(), n));
        Set<String> currentIds = new HashSet<>();
        r.deductions().forEach(d -> currentIds.add(d.findingId().toString()));

        List<Map<String, Object>> added = new ArrayList<>();
        int addedCount = 0;
        for (Deduction d : r.deductions()) {
            if (!previousIds.contains(d.findingId().toString())) {
                addedCount++;
                if (added.size() < MAX_DELTA_ITEMS) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("findingId", d.findingId().toString());
                    m.put("titleKey", d.titleKey());
                    m.put("params", params ? d.params() : Map.of());
                    m.put("severity", d.severity());
                    m.put("value", d.value());
                    added.add(m);
                }
            }
        }
        List<String> goneIds = previousIds.stream().filter(id -> !currentIds.contains(id)).sorted().toList();
        Map<UUID, String> statuses = risk.statuses(goneIds.stream().limit(MAX_DELTA_ITEMS).map(UUID::fromString)
                .toList());
        List<Map<String, Object>> removed = new ArrayList<>();
        for (String id : goneIds.stream().limit(MAX_DELTA_ITEMS).toList()) {
            JsonNode old = previousDeductions.get(id);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("findingId", id);
            m.put("titleKey", old == null ? null : old.path("titleKey").asString());
            m.put("params", params && old != null && old.path("params").isObject()
                    ? json.convertValue(old.path("params"), new TypeReference<Map<String, Object>>() {
                    }) : Map.of());
            m.put("severity", old == null ? null : old.path("severity").asString());
            m.put("value", old == null ? null : old.path("value").asDouble());
            // RESOLVED (a scan no longer sees it), FALSE_POSITIVE / ACCEPTED_RISK (triage) or deleted device
            m.put("status", statuses.getOrDefault(UUID.fromString(id), "REMOVED"));
            removed.add(m);
        }
        List<Map<String, Object>> devicesAdded = newDevices.stream().limit(MAX_DELTA_ITEMS).map(d -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("deviceId", d.id().toString());
            m.put("name", name(d));
            m.put("ip", d.currentIp());
            return m;
        }).toList();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("previousSnapshotId", previous.id().toString());
        out.put("previousScanId", previous.scanId().toString());
        out.put("previousScore", previous.score());
        out.put("scoreChange", r.score() - previous.score());
        out.put("coverageChange", BigDecimal.valueOf(r.coverage().value()).setScale(3, RoundingMode.HALF_UP)
                .subtract(previous.coverage()));
        out.put("newFindingsCount", addedCount);
        out.put("newFindings", added);
        out.put("removedFindingsCount", goneIds.size());
        out.put("removedFindings", removed);
        out.put("newDevicesCount", newDevices.size());
        out.put("newDevices", devicesAdded);
        return out;
    }

    /** Serializes the document; without the findings' parameters if it would be too large. */
    private String bounded(Function<Boolean, Map<String, Object>> build, int maxBytes) {
        String text = json.writeValueAsString(build.apply(true));
        if (text.getBytes(StandardCharsets.UTF_8).length <= maxBytes) {
            return text;
        }
        return json.writeValueAsString(build.apply(false));
    }

    // --- helpers ------------------------------------------------------------------------------

    private static String name(Device d) {
        return d.hostname() != null ? d.hostname() : d.currentIp();
    }

    private Set<String> warnings(String text) {
        if (text == null) {
            return Set.of();
        }
        Set<String> out = new HashSet<>();
        json.readTree(text).forEach(n -> out.add(n.asString()));
        return out;
    }

    private Map<String, Object> parse(String text) {
        return text == null ? Map.of() : json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }
}
