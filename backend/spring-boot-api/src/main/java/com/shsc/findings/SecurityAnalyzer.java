package com.shsc.findings;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.shsc.devices.DeviceRepository;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.findings.FindingRepository.DeviceObservation;
import com.shsc.findings.FindingRepository.DeviceVulnerability;
import com.shsc.findings.FindingRepository.Finding;
import com.shsc.findings.FindingRule.Confidence;
import com.shsc.findings.FindingRule.Detection;
import com.shsc.findings.FindingRule.DeviceView;
import com.shsc.findings.FindingRule.Mapping;
import com.shsc.findings.FindingRule.PortView;
import com.shsc.findings.FindingRule.Scope;
import com.shsc.findings.FindingRule.Severity;
import com.shsc.findings.FindingRule.Type;
import com.shsc.scans.PortRepository;
import com.shsc.scans.PortRepository.StoredPort;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.vulnintel.CpeDictionary;
import com.shsc.vulnintel.CpeDictionary.CpeProduct;
import com.shsc.vulnintel.CpeDictionary.Entry;
import com.shsc.vulnintel.VulnerabilityMatcher;
import com.shsc.vulnintel.VulnerabilityMatcher.Match;
import com.shsc.vulnintel.VulnerabilityMatcher.Quality;
import com.shsc.vulnintel.VulnerabilityRepository;
import com.shsc.vulnintel.VulnerabilityRepository.StoredMatch;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Security analysis of a completed scan (docs/19-SECURITY-ANALYSIS.md): runs in the
 * transaction that completes the scan, after the fingerprinting, on the devices the scan saw
 * (they all belong to the scan's authorized networks: out-of-scope results were already
 * dropped). For each device: CVE matching of the declared products, configuration rules,
 * deduplication by fingerprint, evidence, and resolution of the findings no longer detected
 * on what the scan really covered.
 */
@Service
public class SecurityAnalyzer {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityAnalyzer.class);
    static final String CVE_VERSION_RULE = "cve.version-match";
    static final String CVE_PRODUCT_RULE = "cve.product-only";
    static final int CVE_RULE_VERSION = 1;
    private static final int MAX_CVE_FINDINGS_PER_SERVICE = 100;
    private static final int MAX_PRODUCT_ONLY_ROWS = 200;
    private static final int MAX_EVIDENCE_CHARS = 4000;
    private static final int MAX_PARAMS_CHARS = 2000;

    public record Result(int devices, int detected, int created, int resolved) {
    }

    private final FindingRepository findings;
    private final DeviceRepository devices;
    private final PortRepository ports;
    private final VulnerabilityRepository vulnerabilities;
    private final VulnerabilityMatcher matcher;
    private final CpeDictionary dictionary;
    private final PortLists portLists;
    private final List<FindingRule> rules = FindingRules.all();
    private final JsonMapper json;

    public SecurityAnalyzer(FindingRepository findings, DeviceRepository devices, PortRepository ports,
            VulnerabilityRepository vulnerabilities, VulnerabilityMatcher matcher, CpeDictionary dictionary,
            PortLists portLists, JsonMapper json) {
        this.findings = findings;
        this.devices = devices;
        this.ports = ports;
        this.vulnerabilities = vulnerabilities;
        this.matcher = matcher;
        this.dictionary = dictionary;
        this.portLists = portLists;
        this.json = json;
    }

    /** CVE-based detection and the rows of device_vulnerabilities it links to its finding. */
    private record CveDetection(Detection detection, List<DeviceVulnerability> rows) {
    }

    public Result analyze(Scan scan, Instant now) {
        Map<UUID, Map<String, Map<String, Object>>> methodsByDevice = new LinkedHashMap<>();
        List<Map<String, Object>> igd = new ArrayList<>();
        boolean upnpCovered = true;
        for (DeviceObservation o : findings.observations(scan.id())) {
            Map<String, Object> details = o.detailsJson() == null ? Map.of() : parse(o.detailsJson());
            if (o.deviceId() != null) {
                methodsByDevice.computeIfAbsent(o.deviceId(), k -> new LinkedHashMap<>()).putIfAbsent(o.method(),
                        details);
            }
            if ("UPNP_IGD".equals(o.method())) {
                if (Boolean.TRUE.equals(details.get("controlRefused"))) {
                    upnpCovered = false; // the router's mappings could not be read: nothing to conclude
                } else {
                    igd.add(details);
                }
            }
        }
        Map<CpeProduct, List<StoredMatch>> criteria = new LinkedHashMap<>();
        int detected = 0;
        int created = 0;
        int resolved = 0;
        int analyzed = 0;
        for (Device device : devices.forHome(scan.homeId())) {
            if (!scan.id().equals(device.lastScanId())) {
                continue; // not seen by this scan: nothing to add, nothing to resolve
            }
            analyzed++;
            Map<String, Map<String, Object>> methods = methodsByDevice.getOrDefault(device.id(), Map.of());
            List<PortView> portViews = ports.ofDevice(device.id(), scan.id()).stream().map(this::view).toList();
            List<CveDetection> cves = new ArrayList<>();
            for (PortView p : portViews) {
                cves.addAll(cveDetections(p, criteria));
            }
            boolean kev = cves.stream().anyMatch(c -> Boolean.TRUE.equals(c.detection().evidence().get("knownExploited"))
                    || c.detection().params().get("kev") instanceof Integer n && n > 0);
            String category = device.manualCategory() != null ? device.manualCategory() : device.detectedCategory();
            DeviceView view = new DeviceView(device.id(), category, device.manualCategory() != null, portViews,
                    methods, mappingsTo(device, igd), kev);
            Map<String, Detection> all = new LinkedHashMap<>();
            Map<String, List<DeviceVulnerability>> rows = new LinkedHashMap<>();
            for (CveDetection c : cves) {
                String fp = fingerprint(device.id(), c.detection());
                all.putIfAbsent(fp, c.detection());
                rows.putIfAbsent(fp, c.rows());
            }
            for (FindingRule rule : rules) {
                for (Detection d : rule.evaluate(view)) {
                    all.putIfAbsent(fingerprint(device.id(), d), d);
                }
            }
            for (Map.Entry<String, Detection> e : all.entrySet()) {
                if (store(scan, device, e.getKey(), e.getValue(), rows.get(e.getKey()), now)) {
                    created++;
                }
                detected++;
            }
            Map<String, Object> summary = methods.get("PORTSCAN");
            for (Finding f : findings.active(device.id())) {
                if (all.containsKey(f.fingerprint())) {
                    continue;
                }
                if (covered(scan, f, summary, upnpCovered)) {
                    findings.resolve(f.id(), scan.id(), now);
                    resolved++;
                }
            }
        }
        LOG.info("Security analysis of scan {}: {} devices, {} findings detected ({} new), {} resolved", scan.id(),
                analyzed, detected, created, resolved);
        return new Result(analyzed, detected, created, resolved);
    }

    /** Inserts or updates the finding and adds this scan's evidence; true when created. */
    private boolean store(Scan scan, Device device, String fp, Detection d, List<DeviceVulnerability> cveRows,
            Instant now) {
        FindingRepository.Detected values = new FindingRepository.Detected(d.ruleId(), d.ruleVersion(), d.titleKey(),
                d.recommendationKey(), limited(d.params(), MAX_PARAMS_CHARS), d.severity().name(), d.type().name(),
                d.confidence().name(), d.source(), d.protocol(), d.port(), d.cveId());
        Optional<Finding> existing = findings.lockByFingerprint(device.id(), fp);
        UUID id;
        if (existing.isPresent()) {
            id = existing.get().id();
            findings.redetected(id, values, scan.id(), now);
        } else {
            id = findings.insert(scan.tenantId(), scan.homeId(), device.id(), fp, values, scan.id(), now);
        }
        findings.addEvidence(scan.tenantId(), id, scan.id(), d.source(), limited(d.evidence(), MAX_EVIDENCE_CHARS),
                now);
        if (cveRows != null) {
            findings.replaceVulnerabilities(scan.tenantId(), device.id(), id, scan.id(), cveRows);
        }
        return existing.isEmpty();
    }

    /**
     * Whether the scan looked at what the finding is about: the device was seen (DEVICE), the
     * router's UPnP data was readable (UPNP), the port was in this scan's list and the port scan
     * of the device was not interrupted (PORT).
     */
    boolean covered(Scan scan, Finding f, Map<String, Object> portSummary, boolean upnpCovered) {
        return switch (scope(f)) {
            case DEVICE -> true;
            case UPNP -> upnpCovered;
            case PORT -> f.port() != null && f.protocol() != null && portSummary != null
                    && !Boolean.TRUE.equals(portSummary.get("paused"))
                    && portLists.version().equals(portSummary.get("listVersion"))
                    && scan.profile().equals(portSummary.get("profile"))
                    && portLists.contains(scan.profile(), f.protocol(), f.port());
        };
    }

    static Scope scope(Finding f) {
        if (f.ruleId().startsWith("upnp.")) {
            return Scope.UPNP;
        }
        return f.port() == null ? Scope.DEVICE : Scope.PORT;
    }

    // --- CVE detections -------------------------------------------------------------------

    private List<CveDetection> cveDetections(PortView p, Map<CpeProduct, List<StoredMatch>> cache) {
        if (p.service() == null || p.product() == null) {
            return List.of();
        }
        Optional<Entry> entry = dictionary.lookup(p.service(), p.product());
        if (entry.isEmpty()) {
            return List.of(); // product not in the curated dictionary: no CVE, never a vendor-only match
        }
        Entry e = entry.get();
        List<Match> matches = matcher.match(e, p.version(),
                product -> cache.computeIfAbsent(product, k -> vulnerabilities.matchesOf(k.vendor(), k.product())));
        List<CveDetection> out = new ArrayList<>();
        List<Match> versioned = matches.stream().filter(m -> m.quality() != Quality.PRODUCT_ONLY)
                .sorted(Comparator.comparing((Match m) -> severity(m).ordinal()).reversed()
                        .thenComparing(Match::cveId))
                .limit(MAX_CVE_FINDINGS_PER_SERVICE).toList();
        for (Match m : versioned) {
            boolean confirmed = "HIGH".equals(e.versionConfidence()) && !m.requiresPlatform()
                    && "CONFIRMED".equals(p.serviceStatus());
            Confidence confidence = confirmed ? Confidence.HIGH : m.requiresPlatform() ? Confidence.LOW
                    : Confidence.MEDIUM;
            Detection d = new Detection(CVE_VERSION_RULE, CVE_RULE_VERSION, Scope.PORT, p.protocol(), p.port(),
                    null, m.cveId(), severity(m), confirmed ? Type.CONFIRMED_VULNERABILITY : Type.POTENTIAL_RISK,
                    confidence, "CVE_MATCH",
                    FindingRule.map("cve", m.cveId(), "product", p.product(), "version", p.version(),
                            "cvss", m.cvssScore() == null ? null : m.cvssScore().toPlainString(),
                            "kev", m.kev() ? 1 : null),
                    FindingRule.map("product", p.product(), "version", p.version(), "service", p.service(),
                            "matchQuality", m.quality().name(), "cpe", m.cpe23(), "dictionaryEntry", e.id(),
                            "dictionaryVersion", dictionary.version(), "requiresPlatform", m.requiresPlatform(),
                            "knownExploited", m.kev() ? true : null));
            out.add(new CveDetection(d, List.of(new DeviceVulnerability(m.cveId(), m.quality().name(), m.cpe23(),
                    e.id(), p.version()))));
        }
        List<Match> productOnly = matches.stream().filter(m -> m.quality() == Quality.PRODUCT_ONLY)
                .sorted(Comparator.comparing(Match::cveId)).toList();
        if (!productOnly.isEmpty()) {
            long kev = productOnly.stream().filter(Match::kev).count();
            Detection d = new Detection(CVE_PRODUCT_RULE, CVE_RULE_VERSION, Scope.PORT, p.protocol(), p.port(),
                    e.id(), null, kev > 0 ? Severity.MEDIUM : Severity.LOW, Type.POTENTIAL_RISK, Confidence.LOW,
                    "CVE_MATCH",
                    FindingRule.map("product", p.product(), "version", p.version(), "cves", productOnly.size(),
                            "kev", kev > 0 ? (int) kev : null),
                    FindingRule.map("product", p.product(), "version", p.version(), "service", p.service(),
                            "matchQuality", Quality.PRODUCT_ONLY.name(), "cves", productOnly.size(),
                            "dictionaryEntry", e.id(), "dictionaryVersion", dictionary.version()));
            out.add(new CveDetection(d, productOnly.stream().limit(MAX_PRODUCT_ONLY_ROWS)
                    .map(m -> new DeviceVulnerability(m.cveId(), Quality.PRODUCT_ONLY.name(), m.cpe23(), e.id(),
                            p.version()))
                    .toList()));
        }
        return out;
    }

    /** CVSS severity (LOW when the NVD gives none), one level higher for a known exploited CVE. */
    static Severity severity(Match m) {
        Severity base = switch (m.severity() == null ? "" : m.severity()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM" -> Severity.MEDIUM;
            case "NONE" -> Severity.INFORMATIONAL;
            default -> Severity.LOW;
        };
        return m.kev() ? base.raised() : base;
    }

    // --- helpers --------------------------------------------------------------------------

    private PortView view(StoredPort p) {
        PortRepository.Service s = p.service();
        if (s == null) {
            return new PortView(p.protocol(), p.port(), null, null, null, null, null, null);
        }
        return new PortView(p.protocol(), p.port(), s.name(), s.product(), s.version(), s.status(),
                s.evidenceJson() == null ? null : parse(s.evidenceJson()),
                s.tlsJson() == null ? null : parse(s.tlsJson()));
    }

    /** Enabled mappings of the router(s) whose internal client is one of the device's addresses. */
    private static List<Mapping> mappingsTo(Device device, List<Map<String, Object>> igd) {
        Set<String> addresses = Set.copyOf(device.addresses());
        List<Mapping> out = new ArrayList<>();
        for (Map<String, Object> details : igd) {
            if (!(details.get("portMappings") instanceof List<?> list)) {
                continue;
            }
            for (Object item : list) {
                if (item instanceof Map<?, ?> m && Boolean.TRUE.equals(m.get("enabled"))
                        && m.get("internalClient") instanceof String client && addresses.contains(client)
                        && m.get("externalPort") instanceof Number external && external.intValue() > 0
                        && external.intValue() <= 65535) {
                    String protocol = String.valueOf(m.get("protocol")).toUpperCase(java.util.Locale.ROOT);
                    Integer internal = m.get("internalPort") instanceof Number n ? n.intValue() : null;
                    out.add(new Mapping(protocol.equals("UDP") ? "UDP" : "TCP", external.intValue(), internal,
                            m.get("description") instanceof String d ? d : null));
                }
            }
        }
        return out;
    }

    static String fingerprint(UUID deviceId, Detection d) {
        String key = String.join("|", deviceId.toString(), d.ruleId(), String.valueOf(d.protocol()),
                String.valueOf(d.port()), String.valueOf(d.cveId()), String.valueOf(d.key()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String limited(Map<String, Object> values, int max) {
        String text = json.writeValueAsString(values);
        return text.getBytes(StandardCharsets.UTF_8).length <= max ? text : "{\"truncated\":true}";
    }

    private Map<String, Object> parse(String text) {
        return json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }
}
