package com.shsc.devices.fingerprint;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Value and confidence of every identity field (docs/07-DISCOVERY-FINGERPRINTING.md §3).
 * <p>
 * Each source gives a candidate value with a reliability (H/M/L, table of §3). Concordant
 * candidates are grouped; the value with the most support wins:
 * <ul>
 * <li><b>HIGH</b>: an H source, authoritative for the field (IP/MAC from ARP, host name from
 * the router), or two independent concordant sources of which one H;</li>
 * <li><b>MEDIUM</b>: one M source, or two independent concordant L sources;</li>
 * <li><b>LOW</b>: one weak source;</li>
 * <li>another value from an M or H source = conflict: one level lower, recorded.</li>
 * </ul>
 * A field without sources has no value ("not determined"): nothing is invented. Host names
 * have no conflicts: every variant is kept with its source.
 */
public final class FieldResolver {

    public enum Field { IP, MAC, MANUFACTURER, HOSTNAME, DEVICE_TYPE, MODEL, OS, FIRMWARE }

    public enum Reliability { H, M, L }

    public record Candidate(String value, String source, Reliability reliability) {
    }

    /** One source of the chosen value, or of a conflicting one. */
    public record Source(String source, String value, Reliability reliability, boolean agrees) {
    }

    public record Identification(Field field, String value, Confidence confidence, List<Source> sources,
            boolean conflict) {
    }

    /** OS values (docs/07 §4); TTL 64 only supports the Unix-like family, it never names one. */
    public enum Os { WINDOWS, LINUX, MACOS, ANDROID, IOS, EMBEDDED_LINUX }

    private static final Set<String> UNIX_FAMILY = Set.of("LINUX", "MACOS", "ANDROID", "IOS", "EMBEDDED_LINUX");
    private static final int MAX_VALUE = 255;

    private FieldResolver() {
    }

    /** All the identified fields of a host; the DEVICE_TYPE one comes from the classification. */
    public static Map<Field, Identification> identify(HostEvidence host, ClassificationRules.Classification c) {
        Map<Field, Identification> out = new EnumMap<>(Field.class);
        put(out, resolve(Field.IP, addressCandidates(host)));
        if (host.mac() != null) {
            put(out, resolve(Field.MAC, macCandidates(host)));
        }
        put(out, resolve(Field.HOSTNAME, hostnameCandidates(host)));
        put(out, resolve(Field.MANUFACTURER, manufacturerCandidates(host)));
        put(out, resolve(Field.MODEL, modelCandidates(host)));
        put(out, os(host));
        if (c.category() != DeviceCategory.UNKNOWN_DEVICE) {
            List<Source> sources = c.matches().stream().filter(m -> m.category() == c.category())
                    .map(m -> new Source(String.join("+", m.sources()), m.ruleId(), reliability(m.strength()), true))
                    .toList();
            out.put(Field.DEVICE_TYPE, new Identification(Field.DEVICE_TYPE, c.category().name(), c.confidence(),
                    sources, !c.conflicts().isEmpty()));
        }
        // FIRMWARE: no source reports it reliably before service detection (M9): not determined
        return out;
    }

    /** Overall confidence: from the device type and the maker; HIGH needs both. */
    public static Confidence overall(Map<Field, Identification> fields) {
        Identification type = fields.get(Field.DEVICE_TYPE);
        Identification maker = fields.get(Field.MANUFACTURER);
        if (type == null) {
            return Confidence.LOW;
        }
        if (type.confidence() == Confidence.HIGH && maker != null && maker.confidence().atLeast(Confidence.MEDIUM)) {
            return Confidence.HIGH;
        }
        return type.confidence().atLeast(Confidence.MEDIUM) ? Confidence.MEDIUM : Confidence.LOW;
    }

    static Optional<Identification> resolve(Field field, List<Candidate> candidates) {
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        // group concordant values, one vote per source
        Map<String, Map<String, Candidate>> groups = new LinkedHashMap<>();
        for (Candidate c : candidates) {
            groups.computeIfAbsent(key(field, c.value()), k -> new LinkedHashMap<>())
                    .merge(c.source(), c, (a, b) -> a.reliability().compareTo(b.reliability()) <= 0 ? a : b);
        }
        List<Map<String, Candidate>> ranked = new ArrayList<>(groups.values());
        ranked.sort(Comparator.comparingInt(FieldResolver::support).reversed()
                .thenComparing(g -> best(g).ordinal()));
        Map<String, Candidate> winner = ranked.get(0);
        Candidate display = winner.values().stream().min(Comparator.comparing(Candidate::reliability)).orElseThrow();
        Confidence confidence = confidence(winner);
        boolean conflict = field != Field.HOSTNAME && ranked.stream().skip(1)
                .anyMatch(g -> best(g) != Reliability.L);
        if (conflict) {
            confidence = confidence.lower();
        }
        List<Source> sources = new ArrayList<>();
        winner.values().forEach(c -> sources.add(new Source(c.source(), c.value(), c.reliability(), true)));
        ranked.stream().skip(1).flatMap(g -> g.values().stream())
                .forEach(c -> sources.add(new Source(c.source(), c.value(), c.reliability(), false)));
        return Optional.of(new Identification(field, truncate(display.value()), confidence,
                List.copyOf(sources.subList(0, Math.min(sources.size(), 12))), conflict));
    }

    private static Confidence confidence(Map<String, Candidate> group) {
        Reliability best = best(group);
        if (best == Reliability.H) {
            return Confidence.HIGH;
        }
        if (best == Reliability.M || group.size() >= 2) {
            return Confidence.MEDIUM;
        }
        return Confidence.LOW;
    }

    private static int support(Map<String, Candidate> group) {
        return group.values().stream().mapToInt(c -> switch (c.reliability()) {
            case H -> 3;
            case M -> 2;
            case L -> 1;
        }).sum();
    }

    private static Reliability best(Map<String, Candidate> group) {
        return group.values().stream().map(Candidate::reliability).min(Comparator.naturalOrder()).orElseThrow();
    }

    private static String key(Field field, String value) {
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (field == Field.HOSTNAME) {
            int dot = v.indexOf('.');
            return dot > 0 ? v.substring(0, dot) : v; // "mock-nas.local" = "mock-nas" = "MOCK-NAS"
        }
        if (field == Field.MANUFACTURER) {
            // "Synology Inc." = "Synology", "SAMSUNG ELECTRONICS CO.,LTD" = "Samsung"
            String first = v.replaceAll("[^a-z0-9 ]", " ").trim().split("\\s+")[0];
            return first.isEmpty() ? v : first;
        }
        return v;
    }

    private static List<Candidate> addressCandidates(HostEvidence host) {
        String ip = host.primaryAddress();
        List<Candidate> out = new ArrayList<>();
        for (String method : host.methods()) {
            Reliability r = switch (method) {
                case "ARP", "NDP", "SELF", "TR064", "SNMP" -> Reliability.H;
                default -> Reliability.M;
            };
            out.add(new Candidate(ip, method, r));
        }
        return out;
    }

    private static List<Candidate> macCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        for (String method : host.methods()) {
            if (Set.of("ARP", "NDP", "SELF", "TR064", "SNMP").contains(method)) {
                out.add(new Candidate(host.mac(), method, Reliability.H));
            }
        }
        return out;
    }

    private static List<Candidate> hostnameCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        for (Signal s : host.all("hostname")) {
            Reliability r = HostEvidence.fromRouterTable(s) ? Reliability.H
                    : s.source().equals("RDNS") ? Reliability.L : Reliability.M;
            out.add(new Candidate(s.value(), s.source(), r));
        }
        host.all("ssdp.friendlyName").forEach(s -> out.add(new Candidate(s.value(), "SSDP", Reliability.L)));
        return out;
    }

    private static List<Candidate> manufacturerCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        host.all("mdns.maker").forEach(s -> out.add(new Candidate(s.value(), "MDNS", Reliability.M)));
        host.all("ssdp.manufacturer").forEach(s -> out.add(new Candidate(s.value(), "SSDP", Reliability.M)));
        host.all("router.manufacturer").forEach(s -> out.add(new Candidate(s.value(), s.source(), Reliability.M)));
        // maker of the network card, often not the brand of the product: weak hint only
        host.all("oui").forEach(s -> out.add(new Candidate(s.value(), "OUI", Reliability.L)));
        return out;
    }

    private static List<Candidate> modelCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        host.all("mdns.model").forEach(s -> out.add(new Candidate(s.value(), "MDNS", Reliability.M)));
        host.all("ssdp.modelName").forEach(s -> {
            String number = host.all("ssdp.modelNumber").stream().map(Signal::value).findFirst().orElse(null);
            String model = number == null || s.value().contains(number) ? s.value() : s.value() + " " + number;
            out.add(new Candidate(model, "SSDP", Reliability.M));
        });
        host.all("ipp.model").forEach(s -> out.add(new Candidate(s.value(), "IPP", Reliability.M)));
        host.all("router.model").forEach(s -> out.add(new Candidate(s.value(), s.source(), Reliability.M)));
        return out;
    }

    /**
     * Basic OS fingerprint (docs/07 §4): Apple mDNS data, self-declared SSDP/SNMP banners,
     * NetBIOS, typical host names and the TTL of the ICMP reply. The TTL alone never gives
     * more than LOW, and TTL 64 alone gives nothing (it fits Linux, macOS, iOS and Android).
     */
    private static Optional<Identification> os(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        if (!host.all("mdns.osxvers").isEmpty()) {
            out.add(new Candidate(Os.MACOS.name(), "MDNS", Reliability.M));
        }
        for (Signal s : host.all("mdns.model")) {
            String m = s.value().toLowerCase(Locale.ROOT);
            if (m.startsWith("iphone") || m.startsWith("ipad")) {
                out.add(new Candidate(Os.IOS.name(), "MDNS", Reliability.M));
            } else if (m.matches("^(macbook|imac|macmini|macpro|mac-?studio|mac\\d).*")) {
                out.add(new Candidate(Os.MACOS.name(), "MDNS", Reliability.M));
            }
        }
        for (Signal s : host.all("ssdp.server")) {
            String v = s.value().toLowerCase(Locale.ROOT);
            if (v.contains("windows")) {
                out.add(new Candidate(Os.WINDOWS.name(), "SSDP", Reliability.L));
            } else if (v.contains("android")) {
                out.add(new Candidate(Os.ANDROID.name(), "SSDP", Reliability.L));
            } else if (v.contains("linux")) {
                out.add(new Candidate(Os.LINUX.name(), "SSDP", Reliability.L));
            }
        }
        for (Signal s : host.all("snmp.sysDescr")) {
            if (s.value().toLowerCase(Locale.ROOT).contains("linux")) {
                out.add(new Candidate(Os.EMBEDDED_LINUX.name(), s.source(), Reliability.L));
            }
        }
        if (!host.all("netbios.name").isEmpty()) {
            out.add(new Candidate(Os.WINDOWS.name(), "NETBIOS", Reliability.L)); // Samba answers too: weak
        }
        for (Signal s : host.all("hostname")) {
            String h = s.value().toLowerCase(Locale.ROOT);
            if (h.startsWith("android-") || h.startsWith("android_")) {
                out.add(new Candidate(Os.ANDROID.name(), "HOSTNAME", Reliability.L));
            } else if (h.matches("^desktop-[0-9a-z]{7}(\\..*)?$")) {
                out.add(new Candidate(Os.WINDOWS.name(), "HOSTNAME", Reliability.L));
            }
        }
        Integer ttl = host.ttl();
        if (ttl != null && ttl > 0) {
            if (ttl <= 64) {
                // supports whichever Unix-like value the other sources give, never names one
                Optional<String> unix = out.stream().map(Candidate::value).filter(UNIX_FAMILY::contains).findFirst();
                unix.ifPresent(v -> out.add(new Candidate(v, "TTL", Reliability.L)));
            } else if (ttl <= 128) {
                out.add(new Candidate(Os.WINDOWS.name(), "TTL", Reliability.L));
            } else {
                out.add(new Candidate(Os.EMBEDDED_LINUX.name(), "TTL", Reliability.L));
            }
        }
        Optional<Identification> resolved = resolve(Field.OS, out);
        // the TTL alone: at most LOW
        return resolved.map(id -> id.sources().stream().filter(Source::agrees).allMatch(s -> s.source().equals("TTL"))
                ? new Identification(id.field(), id.value(), Confidence.LOW, id.sources(), id.conflict())
                : id);
    }

    private static Reliability reliability(Strength strength) {
        return switch (strength) {
            case STRONG -> Reliability.H;
            case MODERATE -> Reliability.M;
            case WEAK -> Reliability.L;
        };
    }

    private static void put(Map<Field, Identification> out, Optional<Identification> id) {
        id.ifPresent(i -> out.put(i.field(), i));
    }

    private static String truncate(String v) {
        String t = v.trim();
        return t.length() <= MAX_VALUE ? t : t.substring(0, MAX_VALUE);
    }
}
