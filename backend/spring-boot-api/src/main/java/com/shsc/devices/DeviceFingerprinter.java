package com.shsc.devices;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.shsc.devices.DeviceRepository.Detected;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.devices.DeviceRepository.Identification;
import com.shsc.devices.fingerprint.ClassificationRules;
import com.shsc.devices.fingerprint.ClassificationRules.Classification;
import com.shsc.devices.fingerprint.ClassificationRules.RuleMatch;
import com.shsc.devices.fingerprint.Confidence;
import com.shsc.devices.fingerprint.FieldResolver;
import com.shsc.devices.fingerprint.FieldResolver.Field;
import com.shsc.devices.fingerprint.HostEvidence;
import com.shsc.devices.fingerprint.HostEvidence.PortSeen;
import com.shsc.devices.fingerprint.HostEvidence.Seen;
import com.shsc.devices.oui.OuiRepository;
import com.shsc.scans.PortRepository;
import com.shsc.scans.PortRepository.StoredPort;
import com.shsc.scans.ScanRepository;
import com.shsc.scans.ScanRepository.Observation;
import com.shsc.scans.ScanRepository.Scan;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Turns the observations of a completed scan into the device inventory of the home
 * (docs/17-DEVICE-FINGERPRINTING.md): grouping by MAC (or address), OUI of non-randomized
 * MACs, rule classification, per-field confidence, automatic category history. Runs in the
 * transaction that completes the scan, so the inventory and the scan result never disagree.
 * The manual category is never overwritten: a different detected category is only a
 * suggestion shown to the user.
 */
@Service
public class DeviceFingerprinter {

    private static final int MAX_ADDRESSES = 32;
    private static final int MAX_EXPLAINED_MATCHES = 20;
    private static final int MAX_EXPLAINED_VALUE = 100;

    private final ScanRepository scans;
    private final PortRepository ports;
    private final DeviceRepository devices;
    private final OuiRepository oui;
    private final ClassificationRules rules;
    private final JsonMapper json;

    public DeviceFingerprinter(ScanRepository scans, PortRepository ports, DeviceRepository devices,
            OuiRepository oui, ClassificationRules rules, JsonMapper json) {
        this.scans = scans;
        this.ports = ports;
        this.devices = devices;
        this.oui = oui;
        this.rules = rules;
        this.json = json;
    }

    /** Returns the number of devices created or updated. */
    public int fingerprint(Scan scan, Instant now) {
        int count = 0;
        Map<String, List<StoredPort>> portsByIp = new LinkedHashMap<>();
        ports.ofScan(scan.id()).forEach(p -> portsByIp.computeIfAbsent(p.ip(), k -> new ArrayList<>()).add(p));
        for (List<Observation> group : group(scans.observations(scan.id()))) {
            apply(scan, group, portsByIp, now);
            count++;
        }
        return count;
    }

    /** Same grouping as the scan results: by MAC when one address of the host has it, otherwise per address. */
    static List<List<Observation>> group(List<Observation> all) {
        Map<String, String> macOf = new LinkedHashMap<>();
        for (Observation o : all) {
            if (o.mac() != null) {
                macOf.putIfAbsent(o.ip(), o.mac());
            }
        }
        Map<String, List<Observation>> groups = new LinkedHashMap<>();
        for (Observation o : all) {
            String mac = macOf.get(o.ip());
            groups.computeIfAbsent(mac != null ? "mac:" + mac : "ip:" + o.ip(), k -> new ArrayList<>()).add(o);
        }
        return List.copyOf(groups.values());
    }

    private void apply(Scan scan, List<Observation> group, Map<String, List<StoredPort>> portsByIp, Instant now) {
        List<Seen> seen = group.stream().map(o -> new Seen(o.method(), o.ip(), o.mac(), o.hostname(), details(o)))
                .toList();
        String mac = seen.stream().map(Seen::mac).filter(m -> m != null).findFirst().orElse(null);
        boolean randomized = mac != null && HostEvidence.locallyAdministered(mac);
        String organization = mac == null || randomized ? null : oui.organizationOf(mac).orElse(null);
        List<StoredPort> hostPorts = group.stream().map(Observation::ip).distinct()
                .flatMap(ip -> portsByIp.getOrDefault(ip, List.of()).stream()).toList();
        HostEvidence host = HostEvidence.of(seen, hostPorts.stream().map(this::portSeen).toList(), organization);
        Classification c = rules.classify(host.signals());
        Map<Field, FieldResolver.Identification> fields = FieldResolver.identify(host, c);
        Confidence overall = FieldResolver.overall(fields);
        Instant seenAt = group.stream().map(Observation::observedAt).max(Instant::compareTo).orElse(now);
        List<String> addresses = host.addresses().stream().limit(MAX_ADDRESSES).toList();
        Detected detected = new Detected(host.primaryAddress(), addresses, value(fields, Field.HOSTNAME),
                value(fields, Field.MANUFACTURER), value(fields, Field.MODEL), value(fields, Field.OS),
                c.category().name(), c.confidence() == null ? null : c.confidence().name(), overall.name(),
                explanation(c), c.rulesetVersion(), seenAt, scan.id());

        Optional<Device> existing = devices.lockIdentity(scan.homeId(), host.mac(), host.primaryAddress());
        UUID id;
        if (existing.isPresent()) {
            id = existing.get().id();
            devices.updateDetected(id, detected);
            String old = existing.get().detectedCategory();
            if (!old.equals(detected.category())) {
                devices.insertCategoryChange(scan.tenantId(), id, "AUTO", old, detected.category(), scan.id(), null,
                        now);
            }
        } else {
            id = devices.insert(scan.tenantId(), scan.homeId(), host.mac(), randomized, detected);
            devices.insertCategoryChange(scan.tenantId(), id, "AUTO", null, detected.category(), scan.id(), null, now);
        }
        if (randomized && detected.hostname() != null) {
            // privacy MAC: probably a device already known under the same name
            devices.otherWithHostname(scan.homeId(), detected.hostname(), id).ifPresent(o -> devices.setProbableSameAs(id, o));
        }
        List<Identification> rows = fields.values().stream()
                .map(f -> new Identification(f.field().name(), f.value(), f.confidence().name(),
                        json.writeValueAsString(f.sources()), f.conflict(), scan.id(), c.rulesetVersion(), now))
                .toList();
        devices.replaceIdentifications(scan.tenantId(), id, rows);
        devices.linkObservations(scan.id(), host.addresses(), id);
        ports.linkToDevice(scan.id(), host.addresses(), id);
        ports.replaceProtocols(scan.tenantId(), id, scan.id(), DetectedProtocols.of(group, hostPorts, json));
    }

    private PortSeen portSeen(StoredPort p) {
        PortRepository.Service s = p.service();
        return s == null ? new PortSeen(p.protocol(), p.port(), null, null, null, null)
                : new PortSeen(p.protocol(), p.port(), s.name(), s.product(), s.status(),
                        s.evidenceJson() == null ? null
                        : json.readValue(s.evidenceJson(), new TypeReference<Map<String, Object>>() {
                        }));
    }

    private Map<String, Object> details(Observation o) {
        return o.details() == null ? null : json.readValue(o.details(), new TypeReference<Map<String, Object>>() {
        });
    }

    private static String value(Map<Field, FieldResolver.Identification> fields, Field field) {
        FieldResolver.Identification id = fields.get(field);
        return id == null ? null : id.value();
    }

    /** Why the device got its category: score, threshold rules matched, conflicts. */
    private String explanation(Classification c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("category", c.category().name());
        out.put("confidence", c.confidence() == null ? null : c.confidence().name());
        out.put("score", c.score());
        out.put("conflicts", c.conflicts().stream().map(Enum::name).toList());
        List<Map<String, Object>> matches = new ArrayList<>();
        for (RuleMatch m : c.matches().stream().limit(MAX_EXPLAINED_MATCHES).toList()) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("rule", m.ruleId());
            e.put("category", m.category().name());
            e.put("strength", m.strength().name());
            e.put("sources", List.copyOf(m.sources()));
            e.put("values", m.values().stream()
                    .map(v -> v.length() <= MAX_EXPLAINED_VALUE ? v : v.substring(0, MAX_EXPLAINED_VALUE)).toList());
            matches.add(e);
        }
        out.put("matches", matches);
        return json.writeValueAsString(out);
    }
}
