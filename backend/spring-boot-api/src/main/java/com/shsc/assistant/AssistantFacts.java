package com.shsc.assistant;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The only knowledge of the assistant: data of one home of the tenant, already read under RLS.
 * Every fact has a stable id ({@code S1}, {@code F1}, {@code D1}) that answers must cite.
 * Texts coming from the network (host names, manufacturers) are untrusted and already cleaned.
 */
public record AssistantFacts(String homeName, UUID scanId, Instant dataAsOf, Score score, List<Finding> findings,
        List<Device> devices, boolean truncated) {

    public sealed interface Fact permits Score, Finding, Device {
        String id();

        String kind();

        String label();
    }

    /** Last risk snapshot of the home; {@code score == null} when not computed. */
    public record Score(String id, Integer score, String riskLevel, String rating, String notComputedReason,
            Double coverage, boolean provisional) implements Fact {
        @Override
        public String kind() {
            return "SCORE";
        }

        @Override
        public String label() {
            return score == null ? "-" : score + "/100";
        }
    }

    /** Open, acknowledged or accepted finding (resolved and false positives excluded). */
    public record Finding(String id, String title, String recommendation, String severity, String status,
            String deviceId, String deviceName, String ip) implements Fact {
        @Override
        public String kind() {
            return "FINDING";
        }

        @Override
        public String label() {
            return title;
        }
    }

    public record Device(String id, String name, String ip, String category, String manufacturer) implements Fact {
        @Override
        public String kind() {
            return "DEVICE";
        }

        @Override
        public String label() {
            return name;
        }
    }

    public boolean empty() {
        return score == null && findings.isEmpty() && devices.isEmpty();
    }

    public Map<String, Fact> byId() {
        Map<String, Fact> all = new LinkedHashMap<>();
        if (score != null) {
            all.put(score.id(), score);
        }
        findings.forEach(f -> all.put(f.id(), f));
        devices.forEach(d -> all.put(d.id(), d));
        return all;
    }

    public Optional<Device> device(String id) {
        return devices.stream().filter(d -> d.id().equals(id)).findFirst();
    }

    /** Every text of the facts: an answer may only quote IPs, CVE ids and links found here. */
    public String corpus() {
        List<String> parts = new ArrayList<>();
        parts.add(homeName);
        if (score != null) {
            parts.add(String.valueOf(score.score()));
            parts.add(score.riskLevel());
            parts.add(score.rating());
            parts.add(score.notComputedReason());
        }
        findings.forEach(f -> parts.addAll(List.of(nz(f.title()), nz(f.recommendation()), nz(f.deviceName()),
                nz(f.ip()), nz(f.severity()), nz(f.status()))));
        devices.forEach(d -> parts.addAll(List.of(nz(d.name()), nz(d.ip()), nz(d.category()), nz(d.manufacturer()))));
        return String.join("\n", parts.stream().map(AssistantFacts::nz).toList());
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
