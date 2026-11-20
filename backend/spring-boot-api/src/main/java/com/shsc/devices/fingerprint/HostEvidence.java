package com.shsc.devices.fingerprint;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Everything a scan observed about one host (its observations grouped by MAC, or by address
 * when no MAC is known), turned into {@link Signal}s for the rules and the field resolver.
 * What devices declare about themselves (mDNS, SSDP, UPnP) stays self-declared: it is never
 * treated as verified, only weighted.
 */
public record HostEvidence(String mac, boolean macRandomized, List<String> addresses, Set<String> methods,
        List<Signal> signals, Integer ttl, String ouiOrganization) {

    /** One observation of the scan with its details already parsed. */
    public record Seen(String method, String ip, String mac, String hostname, Map<String, Object> details) {
    }

    /**
     * An open port of the host and its service (M9). A CONFIRMED service answered its protocol
     * and is a source of its own; a PROBABLE one is only the port number (source PORTSCAN).
     */
    public record PortSeen(String protocol, int port, String service, String product, String status,
            Map<String, Object> evidence) {
    }

    /** mDNS TXT keys naming the model / the maker of the product. */
    private static final List<String> TXT_MODEL = List.of("model", "md", "usb_mdl", "product", "am", "ty");
    private static final List<String> TXT_MAKER = List.of("manufacturer", "mfg", "usb_mfg", "vendor");
    /** mDNS TXT keys naming the firmware version (M20); generic keys such as "ver" are left out. */
    private static final List<String> TXT_FIRMWARE = List.of("fw", "fwversion", "fw_version", "firmware",
            "firmwareversion", "swversion", "sw_version");
    /** Methods whose host names come from the router's own tables (DHCP leases, ARP). */
    private static final Set<String> ROUTER_TABLES = Set.of("TR064", "SNMP");

    public static HostEvidence of(List<Seen> observations, String ouiOrganization) {
        return of(observations, List.of(), ouiOrganization);
    }

    public static HostEvidence of(List<Seen> observations, List<PortSeen> ports, String ouiOrganization) {
        String mac = observations.stream().map(Seen::mac).filter(m -> m != null).findFirst()
                .map(m -> m.toLowerCase(Locale.ROOT)).orElse(null);
        boolean randomized = mac != null && locallyAdministered(mac);
        List<String> addresses = observations.stream().map(Seen::ip).distinct()
                .sorted(Comparator.comparing((String ip) -> ip.contains(":")).thenComparing(ip -> ip)).toList();
        Set<String> methods = new LinkedHashSet<>();
        List<Signal> signals = new ArrayList<>();
        Integer ttl = null;
        for (Seen o : observations) {
            methods.add(o.method());
            signals.add(new Signal("method", o.method(), o.method()));
            Map<String, Object> d = o.details() == null ? Map.of() : o.details();
            boolean routerSelf = Boolean.TRUE.equals(d.get("router"));
            if (o.hostname() != null) {
                // the router describing itself (SNMP sysName) is not one of its host tables
                String source = routerSelf ? o.method() + "_SELF" : o.method();
                signals.add(new Signal("hostname", o.hostname(), source));
            }
            switch (o.method()) {
                case "MDNS" -> mdns(d, signals);
                case "SSDP" -> ssdp(d, signals);
                case "ICMP" -> ttl = d.get("ttl") instanceof Number n ? Integer.valueOf(n.intValue()) : ttl;
                case "NETBIOS" -> {
                    if (o.hostname() != null) {
                        signals.add(new Signal("netbios.name", o.hostname(), "NETBIOS"));
                    }
                }
                case "TR064", "SNMP" -> {
                    if (routerSelf) {
                        signals.add(new Signal("router.self", o.method(), o.method()));
                        text(d, "manufacturer").ifPresent(v -> signals.add(new Signal("router.manufacturer", v, o.method())));
                        text(d, "modelName").ifPresent(v -> signals.add(new Signal("router.model", v, o.method())));
                        text(d, "sysDescr").ifPresent(v -> signals.add(new Signal("snmp.sysDescr", v, o.method())));
                    }
                }
                default -> {
                    // ARP, NDP, SELF, RDNS, UPNP_IGD: the method (and host name) is the evidence
                }
            }
        }
        ports.forEach(p -> port(p, signals));
        if (ouiOrganization != null) {
            signals.add(new Signal("oui", ouiOrganization, "OUI"));
        }
        if (randomized) {
            // a private (locally administered) MAC: what phones, tablets and laptops use by default
            signals.add(new Signal("mac.randomized", "true", "MAC"));
        }
        return new HostEvidence(mac, randomized, addresses, methods, List.copyOf(signals), ttl, ouiOrganization);
    }

    /** Values of a field, in observation order. */
    public List<Signal> all(String field) {
        return signals.stream().filter(s -> s.field().equals(field)).toList();
    }

    /** Preferred address: the first IPv4 one, otherwise the first IPv6 one. */
    public String primaryAddress() {
        return addresses.get(0);
    }

    /** Hostnames learnt from the router's tables (DHCP / ARP of the router). */
    public static boolean fromRouterTable(Signal s) {
        return ROUTER_TABLES.contains(s.source());
    }

    /**
     * Locally administered bit of the first octet: the MAC was assigned by software (privacy
     * MAC of phones, virtual interfaces), so it says nothing about the maker.
     */
    public static boolean locallyAdministered(String mac) {
        int first = HexFormat.fromHexDigits(mac.substring(0, 2));
        return (first & 0x02) != 0;
    }

    private static void mdns(Map<String, Object> d, List<Signal> signals) {
        if (d.get("services") instanceof List<?> services) {
            for (Object s : services) {
                if (s instanceof Map<?, ?> m && m.get("type") instanceof String type) {
                    signals.add(new Signal("mdns.service", type, "MDNS"));
                }
            }
        }
        if (d.get("txt") instanceof Map<?, ?> txt) {
            for (Map.Entry<?, ?> e : txt.entrySet()) {
                if (e.getKey() instanceof String key && e.getValue() instanceof String value && !value.isBlank()) {
                    String k = key.toLowerCase(Locale.ROOT);
                    signals.add(new Signal("mdns.txt." + k, value.trim(), "MDNS"));
                    if (TXT_MODEL.contains(k)) {
                        signals.add(new Signal("mdns.model", value.trim(), "MDNS"));
                    }
                    if (TXT_MAKER.contains(k)) {
                        signals.add(new Signal("mdns.maker", value.trim(), "MDNS"));
                    }
                    if (TXT_FIRMWARE.contains(k)) {
                        signals.add(new Signal("mdns.firmware", value.trim(), "MDNS"));
                    }
                    if (k.equals("osxvers")) {
                        signals.add(new Signal("mdns.osxvers", value.trim(), "MDNS"));
                    }
                }
            }
        }
    }

    private static void port(PortSeen p, List<Signal> signals) {
        signals.add(new Signal("port", p.protocol().toLowerCase(Locale.ROOT) + "/" + p.port(), "PORTSCAN"));
        if (p.service() == null) {
            return;
        }
        if (!"CONFIRMED".equals(p.status())) {
            signals.add(new Signal("service.probable", p.service(), "PORTSCAN"));
            return;
        }
        String source = p.service().toUpperCase(Locale.ROOT);
        signals.add(new Signal("service", p.service(), source));
        Map<String, Object> e = p.evidence() == null ? Map.of() : p.evidence();
        switch (p.service()) {
            case "http", "https" -> {
                text(e, "server").ifPresent(v -> signals.add(new Signal("http.server", v, "HTTP")));
                text(e, "title").ifPresent(v -> signals.add(new Signal("http.title", v, "HTTP")));
            }
            case "rtsp" -> text(e, "server").ifPresent(v -> signals.add(new Signal("rtsp.server", v, "RTSP")));
            case "ipp" -> {
                if (p.product() != null) {
                    signals.add(new Signal("ipp.model", p.product(), "IPP"));
                }
                text(e, "firmware").ifPresent(v -> signals.add(new Signal("ipp.firmware", v, "IPP")));
            }
            default -> {
                // the confirmed service itself is the evidence
            }
        }
    }

    private static void ssdp(Map<String, Object> d, List<Signal> signals) {
        text(d, "server").ifPresent(v -> signals.add(new Signal("ssdp.server", v, "SSDP")));
        text(d, "deviceType").ifPresent(v -> signals.add(new Signal("ssdp.type", v, "SSDP")));
        if (d.get("searchTargets") instanceof List<?> targets) {
            targets.stream().filter(String.class::isInstance)
                    .forEach(t -> signals.add(new Signal("ssdp.type", (String) t, "SSDP")));
        }
        text(d, "manufacturer").ifPresent(v -> signals.add(new Signal("ssdp.manufacturer", v, "SSDP")));
        for (String k : List.of("modelName", "modelNumber", "friendlyName")) {
            text(d, k).ifPresent(v -> signals.add(new Signal("ssdp.product", v, "SSDP")));
        }
        text(d, "modelName").ifPresent(v -> signals.add(new Signal("ssdp.modelName", v, "SSDP")));
        text(d, "modelNumber").ifPresent(v -> signals.add(new Signal("ssdp.modelNumber", v, "SSDP")));
        text(d, "friendlyName").ifPresent(v -> signals.add(new Signal("ssdp.friendlyName", v, "SSDP")));
        // non-standard elements of the UPnP descriptor used by several vendors (M20)
        text(d, "firmwareVersion").or(() -> text(d, "softwareVersion"))
                .ifPresent(v -> signals.add(new Signal("ssdp.firmware", v, "SSDP")));
    }

    /**
     * The same host with the data of the Home Assistant device registry whose MACs match it
     * (M20): manufacturer, model and software version, source HOME_ASSISTANT.
     */
    public HostEvidence withHomeAssistant(String manufacturer, String model, String swVersion) {
        List<Signal> extra = new ArrayList<>(signals);
        for (String[] f : new String[][] { { "ha.manufacturer", manufacturer }, { "ha.model", model },
                { "ha.firmware", swVersion } }) {
            if (f[1] != null && !f[1].isBlank()) {
                extra.add(new Signal(f[0], f[1].trim(), "HOME_ASSISTANT"));
            }
        }
        return new HostEvidence(mac, macRandomized, addresses, methods, List.copyOf(extra), ttl, ouiOrganization);
    }

    private static java.util.Optional<String> text(Map<String, Object> d, String key) {
        return d.get(key) instanceof String s && !s.isBlank() ? java.util.Optional.of(s.trim())
                : java.util.Optional.empty();
    }
}
