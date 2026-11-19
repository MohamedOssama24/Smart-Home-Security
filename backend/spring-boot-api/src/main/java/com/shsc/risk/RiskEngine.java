package com.shsc.risk;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Explainable security score of a home, 0–100 (100 = no known problem), and the coverage of the
 * scan it is based on (docs/20-RISK-ENGINE.md, model in docs/09 §3). Pure computation: the
 * inputs are the findings of the home and what the scan was able to look at; every deduction is
 * returned with its factors so the dashboard can answer "why this score?".
 *
 * <p>The weights are part of the versioned model {@link #ENGINE_VERSION}: changing them requires
 * a new version and never rewrites the stored snapshots.
 */
public final class RiskEngine {

    public static final String ENGINE_VERSION = "2026.11-1";

    // --- versioned model (docs/09 §3.1–3.3) ---------------------------------------------------
    static final Map<String, Double> BASE = Map.of("CRITICAL", 30.0, "HIGH", 15.0, "MEDIUM", 6.0, "LOW", 2.0,
            "INFORMATIONAL", 0.0);
    static final Map<String, Double> TYPE_FACTOR = Map.of("CONFIRMED_VULNERABILITY", 1.0, "POTENTIAL_RISK", 0.6,
            "SUSPICIOUS_CONFIGURATION", 0.5, "UNVERIFIED_INFORMATION", 0.0);
    static final Map<String, Double> CONFIDENCE_FACTOR = Map.of("HIGH", 1.0, "MEDIUM", 0.8, "LOW", 0.5);
    static final Set<String> CRITICAL_CATEGORIES = Set.of("ROUTER", "NAS", "IP_CAMERA");
    static final Set<String> COMPUTER_CATEGORIES = Set.of("LAPTOP", "DESKTOP");
    static final double CRITICAL_DEVICE = 1.3;
    static final double COMPUTER = 1.1;
    static final double EXPOSED = 1.5;
    static final double KEV = 1.5;
    static final double DEVICE_CAP = 45.0;
    /** Statuses that count; FALSE_POSITIVE / ACCEPTED_RISK are shown apart, RESOLVED is gone. */
    static final Set<String> COUNTED = Set.of("OPEN", "ACKNOWLEDGED");
    static final Set<String> EXCLUDED = Set.of("FALSE_POSITIVE", "ACCEPTED_RISK");
    /** Finding that makes a device reachable from the Internet (router UPnP forwarding). */
    static final String EXPOSURE_RULE = "upnp.exposed-mapping";

    // coverage (docs/09 §3.2)
    static final double W_HOSTS = 0.40;
    static final double W_DEPTH = 0.25;
    static final double W_TECHNIQUES = 0.20;
    static final double W_ROUTER = 0.15;
    static final Map<String, Double> DEPTH = Map.of("DISCOVERY", 0.2, "QUICK", 0.6, "STANDARD", 0.85, "DEEP", 1.0);
    /** Discovery techniques and their weight; a technique fails when the agent reports X_UNAVAILABLE. */
    static final Map<String, Double> TECHNIQUES = orderedOf("ARP", 0.4, "ICMP", 0.2, "MDNS", 0.2, "SSDP", 0.2);
    static final double PROVISIONAL_BELOW = 0.6;
    static final int PROVISIONAL_CAP = 70;
    static final double EXCELLENT_MIN_COVERAGE = 0.8;

    public static final String PORT_SCAN_REQUIRED = "PORT_SCAN_REQUIRED";

    private RiskEngine() {
    }

    // --- inputs and outputs ---------------------------------------------------------------------

    /** A finding of the home that is not resolved. kev: the finding's CVE is actively exploited. */
    public record FindingInput(UUID id, UUID deviceId, String ruleId, String titleKey, Map<String, Object> params,
            String severity, String type, String confidence, String status, String cveId, boolean kev) {
    }

    public record DeviceInput(UUID id, String name, String ip, String category) {
    }

    /** What the scan could look at. warnings: the scan's warning codes (e.g. MDNS_UNAVAILABLE). */
    public record CoverageInput(String profile, int hostsDiscovered, int hostsAnalyzed, Set<String> warnings,
            boolean routerIntegration) {
    }

    public record Coverage(double value, Map<String, Object> detail) {
    }

    public record Deduction(UUID findingId, UUID deviceId, String ruleId, String titleKey, Map<String, Object> params,
            String severity, String type, String confidence, String status, double base, double typeFactor,
            double confidenceFactor, double criticality, double exposure, double kev, double value) {
    }

    /** raw: sum of the device's deductions; applied: what is subtracted (at most DEVICE_CAP). */
    public record DeviceTotal(UUID deviceId, String name, String ip, String category, double criticality,
            boolean exposed, double raw, double applied, boolean capped, int findings) {
    }

    public record Excluded(UUID findingId, UUID deviceId, String titleKey, Map<String, Object> params,
            String severity, String status) {
    }

    /**
     * score/riskLevel/rating are null when notComputedReason is set. uncappedScore is the score
     * before the low-coverage cap.
     */
    public record Result(Integer score, Integer uncappedScore, String riskLevel, String rating,
            String notComputedReason, Coverage coverage, boolean provisional, double totalDeduction,
            List<Deduction> deductions, List<DeviceTotal> devices, List<Excluded> excluded, int notScored) {
    }

    // --- coverage -----------------------------------------------------------------------------

    public static Coverage coverage(CoverageInput in) {
        double hostRatio = in.hostsDiscovered() <= 0 ? 0.0
                : Math.min(1.0, (double) in.hostsAnalyzed() / in.hostsDiscovered());
        double depth = DEPTH.getOrDefault(in.profile(), 0.0);
        Map<String, Object> techniques = new LinkedHashMap<>();
        double techniqueScore = 0.0;
        for (Map.Entry<String, Double> t : TECHNIQUES.entrySet()) {
            boolean ok = !in.warnings().contains(t.getKey() + "_UNAVAILABLE");
            techniques.put(t.getKey(), ok);
            if (ok) {
                techniqueScore += t.getValue();
            }
        }
        double router = in.routerIntegration() ? 1.0 : 0.0;
        double value = round3(W_HOSTS * hostRatio + W_DEPTH * depth + W_TECHNIQUES * techniqueScore
                + W_ROUTER * router);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("profile", in.profile());
        detail.put("hostsDiscovered", in.hostsDiscovered());
        detail.put("hostsAnalyzed", in.hostsAnalyzed());
        detail.put("hostRatio", round3(hostRatio));
        detail.put("depth", depth);
        detail.put("techniques", techniques);
        detail.put("techniqueScore", round3(techniqueScore));
        detail.put("routerIntegration", in.routerIntegration());
        detail.put("components", orderedOf("hosts", round3(W_HOSTS * hostRatio), "depth", round3(W_DEPTH * depth),
                "techniques", round3(W_TECHNIQUES * techniqueScore), "router", round3(W_ROUTER * router)));
        return new Coverage(value, detail);
    }

    // --- score --------------------------------------------------------------------------------

    /**
     * Score of the home from its non-resolved findings. portData=false (a DISCOVERY scan): the
     * score is not computed, a score without port data would look safer than it is.
     */
    public static Result evaluate(List<FindingInput> findings, Map<UUID, DeviceInput> devices, Coverage coverage,
            boolean portData) {
        boolean provisional = coverage.value() < PROVISIONAL_BELOW;
        List<Excluded> excluded = new ArrayList<>();
        for (FindingInput f : findings) {
            if (EXCLUDED.contains(f.status())) {
                excluded.add(new Excluded(f.id(), f.deviceId(), f.titleKey(), f.params(), f.severity(), f.status()));
            }
        }
        if (!portData) {
            return new Result(null, null, null, null, PORT_SCAN_REQUIRED, coverage, provisional, 0.0, List.of(),
                    List.of(), excluded, 0);
        }
        Set<UUID> exposed = new HashSet<>();
        for (FindingInput f : findings) {
            if (EXPOSURE_RULE.equals(f.ruleId()) && !EXCLUDED.contains(f.status()) && !"RESOLVED".equals(f.status())
                    && f.deviceId() != null) {
                exposed.add(f.deviceId());
            }
        }
        List<Deduction> deductions = new ArrayList<>();
        int notScored = 0;
        for (FindingInput f : findings) {
            if (!COUNTED.contains(f.status())) {
                continue;
            }
            DeviceInput device = devices.get(f.deviceId());
            double base = BASE.getOrDefault(f.severity(), 0.0);
            double type = TYPE_FACTOR.getOrDefault(f.type(), 0.0);
            double confidence = CONFIDENCE_FACTOR.getOrDefault(f.confidence(), 0.5);
            double criticality = criticality(device == null ? null : device.category());
            double exposure = exposed.contains(f.deviceId()) ? EXPOSED : 1.0;
            double kev = f.kev() && f.cveId() != null ? KEV : 1.0;
            double value = base * type * confidence * criticality * exposure * kev;
            if (value <= 0.0) {
                notScored++; // informational or unverified: shown in the findings, no deduction
                continue;
            }
            deductions.add(new Deduction(f.id(), f.deviceId(), f.ruleId(), f.titleKey(), f.params(), f.severity(),
                    f.type(), f.confidence(), f.status(), base, type, confidence, criticality, exposure, kev,
                    round2(value)));
        }
        deductions.sort(Comparator.comparingDouble(Deduction::value).reversed()
                .thenComparing(d -> d.findingId().toString()));

        Map<UUID, List<Deduction>> byDevice = new LinkedHashMap<>();
        for (Deduction d : deductions) {
            byDevice.computeIfAbsent(d.deviceId(), k -> new ArrayList<>()).add(d);
        }
        List<DeviceTotal> totals = new ArrayList<>();
        double total = 0.0;
        for (Map.Entry<UUID, List<Deduction>> e : byDevice.entrySet()) {
            double raw = e.getValue().stream().mapToDouble(Deduction::value).sum();
            double applied = Math.min(raw, DEVICE_CAP);
            total += applied;
            DeviceInput device = devices.get(e.getKey());
            totals.add(new DeviceTotal(e.getKey(), device == null ? null : device.name(),
                    device == null ? null : device.ip(), device == null ? null : device.category(),
                    criticality(device == null ? null : device.category()), exposed.contains(e.getKey()),
                    round2(raw), round2(applied), raw > DEVICE_CAP, e.getValue().size()));
        }
        totals.sort(Comparator.comparingDouble(DeviceTotal::applied).reversed()
                .thenComparing(t -> t.deviceId().toString()));

        // floor: a small deduction is never rounded away (99.5 is 99, not 100)
        int uncapped = (int) Math.floor(Math.max(0.0, 100.0 - total) + 1e-9);
        int score = provisional ? Math.min(uncapped, PROVISIONAL_CAP) : uncapped;
        String level = level(score);
        return new Result(score, uncapped, level, rating(level, coverage.value(), provisional), null, coverage,
                provisional, round2(total), deductions, totals, excluded, notScored);
    }

    /** ≥ 85 LOW · 65–84 MEDIUM · 40–64 HIGH · < 40 CRITICAL. */
    static String level(int score) {
        if (score >= 85) {
            return "LOW";
        }
        if (score >= 65) {
            return "MEDIUM";
        }
        return score >= 40 ? "HIGH" : "CRITICAL";
    }

    /** User-facing judgement: "Excellent" only with a coverage of at least 0.8. */
    static String rating(String level, double coverage, boolean provisional) {
        return switch (level) {
            case "LOW" -> coverage >= EXCELLENT_MIN_COVERAGE && !provisional ? "EXCELLENT" : "GOOD";
            case "MEDIUM" -> "FAIR";
            case "HIGH" -> "POOR";
            default -> "CRITICAL";
        };
    }

    /** An unidentified device is not penalized as such: factor 1.0. */
    static double criticality(String category) {
        if (category == null) {
            return 1.0;
        }
        if (CRITICAL_CATEGORIES.contains(category)) {
            return CRITICAL_DEVICE;
        }
        return COMPUTER_CATEGORIES.contains(category) ? COMPUTER : 1.0;
    }

    static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }

    static double round3(double v) {
        return Math.round(v * 1000.0) / 1000.0;
    }

    private static <V> Map<String, V> orderedOf(Object... kv) {
        Map<String, V> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            @SuppressWarnings("unchecked")
            V value = (V) kv[i + 1];
            out.put((String) kv[i], value);
        }
        return java.util.Collections.unmodifiableMap(out);
    }
}
