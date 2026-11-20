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
import java.util.regex.Pattern;

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

    public enum Field { IP, MAC, MANUFACTURER, HOSTNAME, DEVICE_TYPE, MODEL, OS, FIRMWARE, PRODUCT_CODE, CPE }

    public enum Reliability { H, M, L }

    /**
     * M20 (ADR-076): VERIFIED = declared by the device itself (or observed directly, IP/MAC),
     * confirmed by the user, or two concordant sources with different origins, without
     * conflicts; PROBABLE = any other value; UNKNOWN = no value.
     */
    public enum Status { VERIFIED, PROBABLE, UNKNOWN }

    /**
     * A candidate value. {@code origin}: the original information it derives from (two sources
     * with the same origin are not independent: the host names of the router's tables and of the
     * reverse DNS repeat the same announcement of the device); {@code declared}: the
     * device states the value itself (UPnP descriptor, mDNS TXT, IPP) or it was observed directly.
     */
    public record Candidate(String value, String source, Reliability reliability, String origin, boolean declared) {
        public Candidate(String value, String source, Reliability reliability) {
            this(value, source, reliability, source, false);
        }
    }

    /** One source of the chosen value, or of a conflicting one. */
    public record Source(String source, String value, Reliability reliability, boolean agrees, String origin,
            boolean declared) {
    }

    public record Identification(Field field, String value, Confidence confidence, List<Source> sources,
            boolean conflict, Status status) {
    }

    /** Origins (M20): independence of the sources. */
    static final String ORIGIN_OUI = "OUI";
    static final String ORIGIN_NAME = "NAME_ANNOUNCEMENT";
    static final String ORIGIN_HOME_ASSISTANT = "HOME_ASSISTANT";
    public static final String SOURCE_USER = "USER";
    private static final Set<String> DIRECT = Set.of("ARP", "NDP", "SELF");
    private static final Pattern CORPORATE_SUFFIX = Pattern.compile(
            "(?i)[,.]?\\s+(inc|ltd|llc|corp|corporation|co|gmbh|ag|s\\.?p\\.?a|s\\.?r\\.?l|limited)\\.?$");

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
                    .map(m -> new Source(String.join("+", m.sources()), m.ruleId(), reliability(m.strength()), true,
                            "RULES", false))
                    .toList();
            // derived by rules, never declared: VERIFIED only through the user's manual category
            out.put(Field.DEVICE_TYPE, new Identification(Field.DEVICE_TYPE, c.category().name(), c.confidence(),
                    sources, !c.conflicts().isEmpty(), Status.PROBABLE));
        }
        put(out, resolve(Field.PRODUCT_CODE, productCodeCandidates(host)));
        put(out, resolve(Field.FIRMWARE, firmwareCandidates(host)));
        put(out, cpe(out.get(Field.MANUFACTURER), out.get(Field.MODEL)));
        return out;
    }

    /**
     * Applies a value confirmed by the user (M20): VERIFIED and kept by the scans; a different
     * scanned value stays among the sources and marks a conflict.
     */
    public static Identification confirmed(Field field, String value, Identification scanned) {
        List<Source> sources = new ArrayList<>();
        sources.add(new Source(SOURCE_USER, value, Reliability.H, true, SOURCE_USER, true));
        boolean conflict = false;
        if (scanned != null) {
            boolean agrees = key(field, scanned.value()).equals(key(field, value));
            conflict = !agrees;
            scanned.sources().stream().filter(Source::agrees).limit(11)
                    .forEach(s -> sources.add(new Source(s.source(), s.value(), s.reliability(), agrees, s.origin(),
                            s.declared())));
        }
        return new Identification(field, truncate(value), Confidence.HIGH, List.copyOf(sources), conflict,
                Status.VERIFIED);
    }

    /**
     * CPE 2.3 of the hardware from maker and model (M20). The vendor/product names of the NVD
     * dictionary often differ from the declared ones (ambiguous for IoT): always PROBABLE,
     * VERIFIED only when the user confirms it.
     */
    static Optional<Identification> cpe(Identification maker, Identification model) {
        if (maker == null || model == null) {
            return Optional.empty();
        }
        String vendor = cpeComponent(CORPORATE_SUFFIX.matcher(maker.value().trim()).replaceAll(""));
        String product = cpeComponent(model.value());
        if (vendor.isEmpty() || product.isEmpty()) {
            return Optional.empty();
        }
        String value = "cpe:2.3:h:" + vendor + ":" + product + ":*:*:*:*:*:*:*:*";
        Confidence confidence = maker.confidence().compareTo(model.confidence()) <= 0 ? maker.confidence()
                : model.confidence();
        List<Source> sources = List.of(new Source("DERIVED", maker.value() + " / " + model.value(), Reliability.L,
                true, "MANUFACTURER+MODEL", false));
        return Optional.of(new Identification(Field.CPE, truncate(value), confidence, sources, false,
                Status.PROBABLE));
    }

    /** Lower case, spaces as underscores, CPE 2.3 special characters escaped, non-ASCII dropped. */
    static String cpeComponent(String value) {
        String v = value.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", "_");
        StringBuilder out = new StringBuilder();
        for (char ch : v.toCharArray()) {
            if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
                out.append(ch);
            } else if (ch > 0x20 && ch < 0x7f) {
                out.append('\\').append(ch);
            }
        }
        return out.length() > 100 ? out.substring(0, 100) : out.toString();
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
        winner.values().forEach(c -> sources.add(new Source(c.source(), c.value(), c.reliability(), true, c.origin(),
                c.declared())));
        ranked.stream().skip(1).flatMap(g -> g.values().stream())
                .forEach(c -> sources.add(new Source(c.source(), c.value(), c.reliability(), false, c.origin(),
                        c.declared())));
        return Optional.of(new Identification(field, truncate(display.value()), confidence,
                List.copyOf(sources.subList(0, Math.min(sources.size(), 12))), conflict, status(winner, conflict)));
    }

    /**
     * VERIFIED: no conflict, and the device declares the value, or two concordant sources of
     * different origins, each at least M (heuristics never verify a value).
     */
    static Status status(Map<String, Candidate> winner, boolean conflict) {
        if (conflict) {
            return Status.PROBABLE;
        }
        if (winner.values().stream().anyMatch(Candidate::declared)) {
            return Status.VERIFIED;
        }
        long origins = winner.values().stream().filter(c -> c.reliability() != Reliability.L)
                .map(Candidate::origin).distinct().count();
        return origins >= 2 ? Status.VERIFIED : Status.PROBABLE;
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

    public static String key(Field field, String value) {
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
            out.add(new Candidate(ip, method, r, method, DIRECT.contains(method)));
        }
        return out;
    }

    private static List<Candidate> macCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        for (String method : host.methods()) {
            if (Set.of("ARP", "NDP", "SELF", "TR064", "SNMP").contains(method)) {
                out.add(new Candidate(host.mac(), method, Reliability.H, method, DIRECT.contains(method)));
            }
        }
        return out;
    }

    private static List<Candidate> hostnameCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        for (Signal s : host.all("hostname")) {
            Reliability r = HostEvidence.fromRouterTable(s) ? Reliability.H
                    : s.source().equals("RDNS") ? Reliability.L : Reliability.M;
            // the device announcing its own name (mDNS, NetBIOS, a router describing itself); the
            // router's tables and the reverse DNS repeat the same announcement (same origin)
            boolean declared = s.source().equals("MDNS") || s.source().equals("NETBIOS")
                    || s.source().endsWith("_SELF");
            out.add(new Candidate(s.value(), s.source(), r, declared ? s.source() : ORIGIN_NAME, declared));
        }
        host.all("ssdp.friendlyName").forEach(s -> out.add(new Candidate(s.value(), "SSDP", Reliability.L)));
        return out;
    }

    private static List<Candidate> manufacturerCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        host.all("mdns.maker").forEach(s -> out.add(declared(s, "MDNS")));
        host.all("ssdp.manufacturer").forEach(s -> out.add(declared(s, "SSDP")));
        // the router describing itself (TR-064 DeviceInfo, SNMP): declared by the device
        host.all("router.manufacturer").forEach(s -> out.add(declared(s, s.source())));
        host.all("ha.manufacturer").forEach(s -> out.add(homeAssistant(s)));
        // maker of the network card, often not the brand of the product: weak hint only
        host.all("oui").forEach(s -> out.add(new Candidate(s.value(), "OUI", Reliability.L, ORIGIN_OUI, false)));
        return out;
    }

    private static List<Candidate> modelCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        host.all("mdns.model").forEach(s -> out.add(declared(s, "MDNS")));
        host.all("ssdp.modelName").forEach(s -> {
            String number = host.all("ssdp.modelNumber").stream().map(Signal::value).findFirst().orElse(null);
            String model = number == null || s.value().contains(number) ? s.value() : s.value() + " " + number;
            out.add(new Candidate(model, "SSDP", Reliability.M, "SSDP", true));
        });
        host.all("ipp.model").forEach(s -> out.add(declared(s, "IPP")));
        host.all("router.model").forEach(s -> out.add(declared(s, s.source())));
        host.all("ha.model").forEach(s -> out.add(homeAssistant(s)));
        return out;
    }

    /** Product code / model number (M20): declared by the UPnP descriptor. */
    private static List<Candidate> productCodeCandidates(HostEvidence host) {
        return host.all("ssdp.modelNumber").stream().map(s -> declared(s, "SSDP")).toList();
    }

    /** Firmware (M20): declared by IPP, the UPnP descriptor, mDNS TXT; reported by Home Assistant. */
    private static List<Candidate> firmwareCandidates(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        host.all("ipp.firmware").forEach(s -> out.add(declared(s, "IPP")));
        host.all("ssdp.firmware").forEach(s -> out.add(declared(s, "SSDP")));
        host.all("mdns.firmware").forEach(s -> out.add(declared(s, "MDNS")));
        host.all("ha.firmware").forEach(s -> out.add(homeAssistant(s)));
        return out;
    }

    private static Candidate declared(Signal s, String source) {
        return new Candidate(s.value(), source, Reliability.M, source, true);
    }

    /** Home Assistant registry: an integration configured by the user; independent origin, not the device. */
    private static Candidate homeAssistant(Signal s) {
        return new Candidate(s.value(), ORIGIN_HOME_ASSISTANT, Reliability.M, ORIGIN_HOME_ASSISTANT, false);
    }

    /**
     * Basic OS fingerprint (docs/07 §4): Apple mDNS data, self-declared SSDP/SNMP banners,
     * NetBIOS, typical host names and the TTL of the ICMP reply. The TTL alone never gives
     * more than LOW, and TTL 64 alone gives nothing (it fits Linux, macOS, iOS and Android).
     */
    private static Optional<Identification> os(HostEvidence host) {
        List<Candidate> out = new ArrayList<>();
        if (!host.all("mdns.osxvers").isEmpty()) {
            out.add(new Candidate(Os.MACOS.name(), "MDNS", Reliability.M, "MDNS", true)); // declared version
        }
        for (Signal s : host.all("mdns.model")) {
            // inferred from the model name, not declared
            String m = s.value().toLowerCase(Locale.ROOT);
            if (m.startsWith("iphone") || m.startsWith("ipad")) {
                out.add(new Candidate(Os.IOS.name(), "MDNS", Reliability.M, "MDNS_MODEL", false));
            } else if (m.matches("^(macbook|imac|macmini|macpro|mac-?studio|mac\\d).*")) {
                out.add(new Candidate(Os.MACOS.name(), "MDNS", Reliability.M, "MDNS_MODEL", false));
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
                ? new Identification(id.field(), id.value(), Confidence.LOW, id.sources(), id.conflict(),
                        id.status())
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

    static String truncate(String v) {
        String t = v.trim();
        return t.length() <= MAX_VALUE ? t : t.substring(0, MAX_VALUE);
    }
}
