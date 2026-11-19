package com.shsc.findings;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.shsc.findings.FindingRule.Confidence;
import com.shsc.findings.FindingRule.Detection;
import com.shsc.findings.FindingRule.DeviceView;
import com.shsc.findings.FindingRule.Mapping;
import com.shsc.findings.FindingRule.PortView;
import com.shsc.findings.FindingRule.Scope;
import com.shsc.findings.FindingRule.Severity;
import com.shsc.findings.FindingRule.Type;

/**
 * Catalog of the configuration rules (docs/19-SECURITY-ANALYSIS.md §4, adapted from
 * docs/09-SECURITY-ANALYSIS-RISK.md §1.2). Each rule is a class with an id and a version; a
 * change of behaviour increments the version (stored with every finding). Rules only read the
 * scan results: they never send anything to a device, never try a password or a default
 * community.
 */
public final class FindingRules {

    private FindingRules() {
    }

    /** Every rule, in evaluation order (the CVE rules live in {@link SecurityAnalyzer}). */
    public static List<FindingRule> all() {
        return List.of(new TelnetOpen(), new FtpCleartext(), new HttpLoginCleartext(), new TlsLegacyProtocol(),
                new TlsCertificateExpired(), new SmbV1Enabled(), new UpnpExposedMapping(), new UpnpIgdEnabled(),
                new Tr069Exposed(), new RtspOpen(), new MqttCleartext(), new SnmpEnabled(), new DnsOpenResolver(),
                new UnknownDevice());
    }

    /** A rule evaluated on each port of the device. */
    abstract static class PortRule implements FindingRule {
        @Override
        public List<Detection> evaluate(DeviceView device) {
            List<Detection> out = new ArrayList<>();
            for (PortView p : device.ports()) {
                Detection d = detect(device, p);
                if (d != null) {
                    out.add(d);
                }
            }
            return out;
        }

        abstract Detection detect(DeviceView device, PortView port);

        Detection on(PortView p, Severity severity, Type type, Confidence confidence, Map<String, Object> params,
                Map<String, Object> evidence) {
            return new Detection(id(), version(), Scope.PORT, p.protocol(), p.port(), null, null, severity, type,
                    confidence, "PORTSCAN", params, evidence);
        }

        static boolean is(PortView p, String service) {
            return service.equals(p.service());
        }

        /** HIGH when the protocol answered as such, MEDIUM when only deduced from the port. */
        static Confidence identified(PortView p) {
            return "CONFIRMED".equals(p.serviceStatus()) ? Confidence.HIGH : Confidence.MEDIUM;
        }

        static Map<String, Object> service(PortView p) {
            return FindingRule.map("service", p.service(), "product", p.product(), "version", p.version(),
                    "serviceStatus", p.serviceStatus());
        }
    }

    /** Telnet: credentials and session in clear text. */
    static final class TelnetOpen extends PortRule {
        public String id() { return "telnet.open"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            return is(p, "telnet") ? on(p, Severity.HIGH, Type.SUSPICIOUS_CONFIGURATION, identified(p),
                    FindingRule.map("port", p.port()), service(p)) : null;
        }
    }

    /** FTP without TLS. */
    static final class FtpCleartext extends PortRule {
        public String id() { return "ftp.cleartext"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            return is(p, "ftp") && p.tls() == null ? on(p, Severity.MEDIUM, Type.SUSPICIOUS_CONFIGURATION,
                    identified(p), FindingRule.map("port", p.port()), service(p)) : null;
        }
    }

    /** A login page or HTTP authentication over plain HTTP that does not redirect to HTTPS. */
    static final class HttpLoginCleartext extends PortRule {
        public String id() { return "http.login-cleartext"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            Map<String, Object> ev = p.evidence();
            if (!is(p, "http") || p.tls() != null || ev == null || Boolean.TRUE.equals(ev.get("redirectsToHttps"))) {
                return null;
            }
            boolean form = Boolean.TRUE.equals(ev.get("loginForm"));
            Object auth = ev.get("authenticate");
            boolean httpAuth = auth instanceof String s && (s.equalsIgnoreCase("Basic") || s.equalsIgnoreCase("Digest"));
            if (!form && !httpAuth) {
                return null;
            }
            return on(p, Severity.MEDIUM, Type.SUSPICIOUS_CONFIGURATION, Confidence.HIGH,
                    FindingRule.map("port", p.port()),
                    FindingRule.map("status", ev.get("status"), "loginForm", form ? true : null,
                            "authenticate", httpAuth ? auth : null, "title", ev.get("title"), "server", ev.get("server")));
        }
    }

    /** TLS 1.0 / 1.1 accepted (MEDIUM when nothing newer is supported). */
    static final class TlsLegacyProtocol extends PortRule {
        public String id() { return "tls.legacy-protocol"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            if (p.tls() == null || !(p.tls().get("versions") instanceof List<?> versions)) {
                return null;
            }
            List<String> legacy = versions.stream().map(String::valueOf)
                    .filter(v -> v.equals("TLS1.0") || v.equals("TLS1.1")).toList();
            if (legacy.isEmpty()) {
                return null;
            }
            boolean onlyLegacy = versions.stream().map(String::valueOf)
                    .noneMatch(v -> v.equals("TLS1.2") || v.equals("TLS1.3"));
            return on(p, onlyLegacy ? Severity.MEDIUM : Severity.LOW, Type.SUSPICIOUS_CONFIGURATION, Confidence.HIGH,
                    FindingRule.map("port", p.port(), "versions", String.join(", ", legacy)),
                    FindingRule.map("versions", versions));
        }
    }

    /** Expired certificate (inspected, never trusted). */
    static final class TlsCertificateExpired extends PortRule {
        public String id() { return "tls.certificate-expired"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            if (p.tls() == null || !Boolean.TRUE.equals(p.tls().get("expired"))) {
                return null;
            }
            return on(p, Severity.LOW, Type.SUSPICIOUS_CONFIGURATION, Confidence.HIGH,
                    FindingRule.map("port", p.port(), "notAfter", p.tls().get("notAfter")),
                    FindingRule.map("notAfter", p.tls().get("notAfter"), "selfSigned", p.tls().get("selfSigned")));
        }
    }

    /** SMBv1 negotiated. */
    static final class SmbV1Enabled extends PortRule {
        public String id() { return "smb.v1-enabled"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            if (!is(p, "smb") || p.evidence() == null || !Boolean.TRUE.equals(p.evidence().get("smb1"))) {
                return null;
            }
            return on(p, Severity.HIGH, Type.SUSPICIOUS_CONFIGURATION, Confidence.HIGH,
                    FindingRule.map("port", p.port()), FindingRule.map("smb1", true));
        }
    }

    /** UPnP port mapping that exposes an administration or camera port of the device to the Internet. */
    static final class UpnpExposedMapping implements FindingRule {
        static final Set<Integer> SENSITIVE = Set.of(21, 22, 23, 80, 139, 443, 445, 554, 2323, 3389, 5900, 7547, 8000,
                8080, 8081, 8443, 8554, 8888, 9000, 10554, 34567, 37777);

        public String id() { return "upnp.exposed-mapping"; }
        public int version() { return 1; }

        public List<Detection> evaluate(DeviceView d) {
            List<Detection> out = new ArrayList<>();
            boolean camera = "IP_CAMERA".equals(d.category());
            for (Mapping m : d.mappings()) {
                int target = m.internalPort() == null ? m.externalPort() : m.internalPort();
                if (!camera && !SENSITIVE.contains(target)) {
                    continue;
                }
                out.add(new Detection(id(), version(), Scope.UPNP, m.protocol(), m.externalPort(), null, null,
                        d.hasKev() ? Severity.CRITICAL : Severity.HIGH, Type.POTENTIAL_RISK, Confidence.MEDIUM,
                        "UPNP_IGD", FindingRule.map("externalPort", m.externalPort(), "internalPort", target),
                        FindingRule.map("protocol", m.protocol(), "externalPort", m.externalPort(),
                                "internalPort", m.internalPort(), "description", m.description(),
                                "knownExploited", d.hasKev() ? true : null)));
            }
            return out;
        }
    }

    /** The router accepts UPnP IGD port mapping requests from the LAN. */
    static final class UpnpIgdEnabled implements FindingRule {
        public String id() { return "upnp.igd-enabled"; }
        public int version() { return 1; }

        public List<Detection> evaluate(DeviceView d) {
            Map<String, Object> igd = d.methods().get("UPNP_IGD");
            if (igd == null) {
                return List.of();
            }
            Object mappings = igd.get("portMappings");
            return List.of(new Detection(id(), version(), Scope.UPNP, null, null, null, null, Severity.LOW,
                    Type.POTENTIAL_RISK, Confidence.HIGH, "UPNP_IGD",
                    FindingRule.map("mappings", mappings instanceof List<?> l ? l.size() : null),
                    FindingRule.map("serviceType", igd.get("serviceType"),
                            "mappings", mappings instanceof List<?> l ? l.size() : null)));
        }
    }

    /** TR-069 (CWMP) port reachable from the LAN: management by the provider, informational. */
    static final class Tr069Exposed extends PortRule {
        public String id() { return "tr069.exposed"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            return "TCP".equals(p.protocol()) && p.port() == 7547 ? on(p, Severity.INFORMATIONAL,
                    Type.UNVERIFIED_INFORMATION, Confidence.LOW, FindingRule.map("port", p.port()), service(p)) : null;
        }
    }

    /** RTSP video stream service (only OPTIONS was sent: no stream is opened). */
    static final class RtspOpen extends PortRule {
        public String id() { return "rtsp.open"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            if (!is(p, "rtsp")) {
                return null;
            }
            Object auth = p.evidence() == null ? null : p.evidence().get("authRequired");
            return on(p, Severity.LOW, Type.POTENTIAL_RISK, identified(p), FindingRule.map("port", p.port()),
                    FindingRule.map("status", p.evidence() == null ? null : p.evidence().get("status"),
                            "authRequired", auth, "server", p.evidence() == null ? null : p.evidence().get("server")));
        }
    }

    /** MQTT without TLS (1883). */
    static final class MqttCleartext extends PortRule {
        public String id() { return "mqtt.cleartext"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            return is(p, "mqtt") && p.tls() == null && p.port() == 1883 ? on(p, Severity.MEDIUM,
                    Type.POTENTIAL_RISK, identified(p), FindingRule.map("port", p.port()), service(p)) : null;
        }
    }

    /** SNMP answering (no community is ever tried: only the agent's unauthenticated discovery). */
    static final class SnmpEnabled extends PortRule {
        public String id() { return "snmp.enabled"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            return is(p, "snmp") && "UDP".equals(p.protocol()) ? on(p, Severity.LOW, Type.POTENTIAL_RISK,
                    identified(p), FindingRule.map("port", p.port()), service(p)) : null;
        }
    }

    /** DNS server offering recursion on a device that is not the router. */
    static final class DnsOpenResolver extends PortRule {
        public String id() { return "dns.open-resolver"; }
        public int version() { return 1; }

        Detection detect(DeviceView d, PortView p) {
            if (!is(p, "dns") || "ROUTER".equals(d.category()) || p.evidence() == null
                    || !Boolean.TRUE.equals(p.evidence().get("recursionAvailable"))) {
                return null;
            }
            return on(p, Severity.LOW, Type.POTENTIAL_RISK, Confidence.MEDIUM, FindingRule.map("port", p.port()),
                    FindingRule.map("recursionAvailable", true, "rcode", p.evidence().get("rcode")));
        }
    }

    /** Device not identified (no manual category either): the user should check what it is. */
    static final class UnknownDevice implements FindingRule {
        public String id() { return "device.unknown"; }
        public int version() { return 1; }

        public List<Detection> evaluate(DeviceView d) {
            if (!"UNKNOWN_DEVICE".equals(d.category()) || d.manualCategory()) {
                return List.of();
            }
            return List.of(new Detection(id(), version(), Scope.DEVICE, null, null, null, null,
                    Severity.INFORMATIONAL, Type.UNVERIFIED_INFORMATION, Confidence.LOW, "FINGERPRINT",
                    FindingRule.map(), FindingRule.map("methods", List.copyOf(d.methods().keySet()))));
        }
    }
}
