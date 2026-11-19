package com.shsc.findings;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A versioned security rule (docs/19-SECURITY-ANALYSIS.md §4). It only reads what the scan of
 * an authorized network observed (ports, services, protocols, router data): no rule sends
 * anything to a device.
 */
public interface FindingRule {

    String id();

    int version();

    List<Detection> evaluate(DeviceView device);

    enum Severity {
        INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL;

        /** One level up (a known exploited vulnerability), CRITICAL at most. */
        Severity raised() {
            return this == CRITICAL ? CRITICAL : values()[ordinal() + 1];
        }
    }

    enum Type { CONFIRMED_VULNERABILITY, POTENTIAL_RISK, SUSPICIOUS_CONFIGURATION, UNVERIFIED_INFORMATION }

    enum Confidence { HIGH, MEDIUM, LOW }

    /**
     * What a scan must have covered to RESOLVE a finding no longer detected: the port (probed
     * by this scan's port list), the device (seen by the scan) or the router's UPnP data.
     */
    enum Scope { PORT, DEVICE, UPNP }

    /** One port of the device with its service (null fields when not identified). */
    record PortView(String protocol, int port, String service, String product, String version, String serviceStatus,
            Map<String, Object> evidence, Map<String, Object> tls) {
    }

    /** An UPnP IGD port mapping (declared by the router) that targets the device. */
    record Mapping(String protocol, int externalPort, Integer internalPort, String description) {
    }

    /**
     * What the scan knows of one device. {@code methods}: discovery methods that saw it (with
     * their details); {@code hasKev}: a known exploited CVE matched one of its services.
     */
    record DeviceView(UUID id, String category, boolean manualCategory, List<PortView> ports,
            Map<String, Map<String, Object>> methods, List<Mapping> mappings, boolean hasKev) {
    }

    /** A rule result; {@code key} distinguishes several detections of one rule on one port. */
    record Detection(String ruleId, int ruleVersion, Scope scope, String protocol, Integer port, String key,
            String cveId, Severity severity, Type type, Confidence confidence, String source,
            Map<String, Object> params, Map<String, Object> evidence) {

        String titleKey() {
            return "findings.rule." + ruleId.replace('.', '-') + ".title";
        }

        String recommendationKey() {
            return "findings.rule." + ruleId.replace('.', '-') + ".recommendation";
        }
    }

    /** Small ordered map without null values (params and evidence). */
    static Map<String, Object> map(Object... keyValues) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            if (keyValues[i + 1] != null) {
                out.put((String) keyValues[i], keyValues[i + 1]);
            }
        }
        return out;
    }
}
