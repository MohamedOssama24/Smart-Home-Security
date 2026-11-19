package com.shsc.devices;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.shsc.scans.PortRepository.Protocol;
import com.shsc.scans.PortRepository.StoredPort;
import com.shsc.scans.ScanRepository.Observation;

import tools.jackson.databind.json.JsonMapper;

/**
 * Protocols a device spoke in one scan (docs/18-PORT-SCANNING.md §5): the discovery
 * protocols it answered (mDNS, SSDP, UPnP IGD, SNMP, NetBIOS, TR-064) and the services found
 * on its open ports. A service that answered its protocol is HIGH; a service guessed from the
 * port number alone is LOW. Used by the classification and, later, by the risk rules.
 */
final class DetectedProtocols {

    private static final Map<String, String> DISCOVERY = Map.of("MDNS", "MDNS", "SSDP", "SSDP", "UPNP_IGD", "UPNP",
            "SNMP", "SNMP", "NETBIOS", "NETBIOS", "TR064", "TR064");

    private DetectedProtocols() {
    }

    private static final class Entry {
        String confidence;
        String source;
        final List<String> ports = new ArrayList<>();

        Entry(String confidence, String source) {
            this.confidence = confidence;
            this.source = source;
        }
    }

    static List<Protocol> of(List<Observation> observations, List<StoredPort> ports, JsonMapper json) {
        Map<String, Entry> out = new TreeMap<>();
        for (Observation o : observations) {
            String protocol = DISCOVERY.get(o.method());
            if (protocol != null) {
                out.computeIfAbsent(protocol, k -> new Entry("HIGH", "DISCOVERY"));
            }
        }
        for (StoredPort p : ports) {
            if (p.service() == null) {
                continue;
            }
            String protocol = p.service().name().toUpperCase(Locale.ROOT).replace('-', '_');
            String confidence = "CONFIRMED".equals(p.service().status()) ? "HIGH" : "LOW";
            Entry e = out.computeIfAbsent(protocol, k -> new Entry(confidence, "PORTSCAN"));
            if ("HIGH".equals(confidence)) {
                e.confidence = "HIGH";
            }
            if (e.ports.size() < 16) {
                e.ports.add(p.protocol().toLowerCase(Locale.ROOT) + "/" + p.port());
            }
        }
        return out.entrySet().stream().map(e -> {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("source", e.getValue().ports.isEmpty() ? e.getValue().source : "PORTSCAN");
            if (!e.getValue().ports.isEmpty()) {
                details.put("ports", e.getValue().ports);
            }
            return new Protocol(e.getKey(), json.writeValueAsString(details), e.getValue().confidence);
        }).toList();
    }
}
