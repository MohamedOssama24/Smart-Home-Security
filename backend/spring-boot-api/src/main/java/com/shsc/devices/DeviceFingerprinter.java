package com.shsc.devices;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
import com.shsc.devices.images.DeviceImageRepository;
import com.shsc.devices.oui.OuiRepository;
import com.shsc.integrations.HomeAssistantRepository;
import com.shsc.integrations.HomeAssistantRepository.GatewayDevice;
import com.shsc.people.PeopleResolver;
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
    static final java.time.Duration EPHEMERAL_RETENTION = java.time.Duration.ofDays(30);
    static final int MAX_ADDRESS_HISTORY = 256;
    /** Global IPv6 addresses read passively from the agent's neighbour table, attached to an in-scope observation. */
    static final String GLOBAL_IPV6_DETAIL = "globalIpv6";
    static final int MAX_GLOBAL_IPV6_PER_OBSERVATION = 8;

    private final ScanRepository scans;
    private final PortRepository ports;
    private final DeviceRepository devices;
    private final OuiRepository oui;
    private final ClassificationRules rules;
    private final JsonMapper json;
    private final HomeAssistantRepository homeAssistant;
    private final DeviceImageRepository images;
    private final PeopleResolver people;

    public DeviceFingerprinter(ScanRepository scans, PortRepository ports, DeviceRepository devices,
            OuiRepository oui, ClassificationRules rules, JsonMapper json, HomeAssistantRepository homeAssistant,
            DeviceImageRepository images, PeopleResolver people) {
        this.people = people;
        this.images = images;
        this.scans = scans;
        this.ports = ports;
        this.devices = devices;
        this.oui = oui;
        this.rules = rules;
        this.json = json;
        this.homeAssistant = homeAssistant;
    }

    /** Returns the number of devices created or updated. */
    public int fingerprint(Scan scan, Instant now) {
        int count = 0;
        Map<String, List<StoredPort>> portsByIp = new LinkedHashMap<>();
        ports.ofScan(scan.id()).forEach(p -> portsByIp.computeIfAbsent(p.ip(), k -> new ArrayList<>()).add(p));
        Map<String, UUID> owners = devices.interfaceOwners(scan.homeId());
        Map<String, GatewayDevice> gateway = homeAssistant.devicesByMac(scan.id());
        List<Group> groups = adoptKnownMac(group(scans.observations(scan.id()), owners.keySet()),
                devices.macByCurrentAddress(scan.homeId()));
        for (Group group : joinByDevice(groups, owners)) {
            apply(scan, group, portsByIp, gateway, now);
            count++;
        }
        for (UUID[] twin : devices.addressOnlyTwins(scan.homeId())) {
            devices.merge(twin[0], twin[1]);
        }
        refreshOutdated(scan, now);
        people.resolve(scan.homeId(), scan.id(), gateway, now); // M24: people named by the devices or seen logging on
        return count;
    }

    static final int MAX_REFRESHED_PER_SCAN = 100;

    /**
     * A host seen without MAC (it answered ping, ARP gave nothing in this scan) at the current
     * address of a known device with a MAC is that device, unless that MAC was seen elsewhere in
     * this scan (then the address was given to another host): without this, every ping-only
     * sighting created a second, address-only device.
     */
    static List<Group> adoptKnownMac(List<Group> groups, Map<String, String> macByAddress) {
        Set<String> seenMacs = new HashSet<>();
        groups.stream().map(Group::mac).filter(m -> m != null).forEach(seenMacs::add);
        List<Group> out = new ArrayList<>();
        for (Group g : groups) {
            String known = g.mac() != null ? null
                    : g.observations().stream().map(Observation::ip).distinct().count() == 1
                            ? macByAddress.get(g.observations().get(0).ip()) : null;
            out.add(known != null && !seenMacs.contains(known)
                    ? new Group(known.toLowerCase(Locale.ROOT), g.observations()) : g);
        }
        return out;
    }

    /**
     * Devices not seen in this scan keep the result computed when they were last seen: after a
     * new ruleset or an OUI registry import they are classified again from the observations of
     * their last scan (no traffic), so offline devices do not stay with outdated values.
     */
    private void refreshOutdated(Scan scan, Instant now) {
        for (Device d : devices.outdated(scan.homeId(), scan.id(), rules.version(), MAX_REFRESHED_PER_SCAN)) {
            reclassify(d, now);
        }
    }

    /**
     * Computes the device again from the observations of its last scan (no traffic). Used for
     * outdated devices and after the deletion of a scan (the last scan of the device changed).
     * False when that scan has no observation of the device.
     */
    public boolean reclassify(Device d, Instant now) {
        Optional<Scan> last = scans.find(d.lastScanId());
        List<Observation> observations = scans.observationsOfDevice(d.lastScanId(), d.id());
        if (last.isEmpty() || observations.isEmpty()) {
            return false;
        }
        Map<String, List<StoredPort>> portsByIp = new LinkedHashMap<>();
        ports.ofScan(d.lastScanId()).forEach(p -> portsByIp.computeIfAbsent(p.ip(), k -> new ArrayList<>()).add(p));
        apply(last.get(), new Group(d.mac(), observations), portsByIp, homeAssistant.devicesByMac(d.lastScanId()), now);
        return true;
    }

    /** Observations of one host: its MAC (seen, or derived from an EUI-64 IPv6 address) when known. */
    record Group(String mac, List<Observation> observations) {
    }

    /**
     * Same grouping as the scan results: by MAC when one address of the host has it, otherwise per
     * address. An IPv6 address seen without MAC joins the host whose MAC is embedded in its EUI-64
     * interface identifier, when that MAC is seen in the scan or is a known interface of the home
     * (M19): an EUI-64 identifier is the MAC of the interface holding the address.
     */
    static List<Group> group(List<Observation> all, Set<String> knownMacs) {
        Map<String, String> macOf = new LinkedHashMap<>();
        for (Observation o : all) {
            if (o.mac() != null) {
                macOf.putIfAbsent(o.ip(), o.mac().toLowerCase(Locale.ROOT));
            }
        }
        Set<String> seenMacs = new HashSet<>(macOf.values());
        for (Observation o : all) {
            if (!macOf.containsKey(o.ip())) {
                Addresses.eui64Mac(o.ip())
                        .filter(m -> seenMacs.contains(m) || knownMacs.contains(m))
                        .ifPresent(m -> macOf.put(o.ip(), m));
            }
        }
        Map<String, Group> groups = new LinkedHashMap<>();
        for (Observation o : all) {
            String mac = macOf.get(o.ip());
            groups.computeIfAbsent(mac != null ? "mac:" + mac : "ip:" + o.ip(),
                    k -> new Group(mac, new ArrayList<>())).observations().add(o);
        }
        return List.copyOf(groups.values());
    }

    /**
     * Groups whose MACs are interfaces of the same device (confirmed by the user, M19) form one
     * host: the device is updated once with all its addresses. The first group gives the MAC.
     */
    static List<Group> joinByDevice(List<Group> groups, Map<String, UUID> owners) {
        Map<Object, Group> joined = new LinkedHashMap<>();
        for (Group g : groups) {
            UUID owner = g.mac() == null ? null : owners.get(g.mac());
            Object key = owner != null ? owner : g;
            Group current = joined.get(key);
            if (current == null) {
                joined.put(key, new Group(g.mac(), new ArrayList<>(g.observations())));
            } else {
                current.observations().addAll(g.observations());
            }
        }
        return List.copyOf(joined.values());
    }

    private void apply(Scan scan, Group g, Map<String, List<StoredPort>> portsByIp, Map<String, GatewayDevice> gateway,
            Instant now) {
        List<Observation> group = g.observations();
        String mac = g.mac();
        List<Seen> seen = group.stream()
                .map(o -> new Seen(o.method(), o.ip(), o.mac() != null ? o.mac() : mac, o.hostname(), details(o)))
                .toList();
        boolean randomized = mac != null && HostEvidence.locallyAdministered(mac);
        String organization = mac == null || randomized ? null : oui.organizationOf(mac).orElse(null);
        List<StoredPort> hostPorts = group.stream().map(Observation::ip).distinct()
                .flatMap(ip -> portsByIp.getOrDefault(ip, List.of()).stream()).toList();
        HostEvidence host = HostEvidence.of(seen, hostPorts.stream().map(this::portSeen).toList(), organization);
        // Home Assistant registry entry with one of the MACs of the host (M20)
        Optional<GatewayDevice> ha = group.stream().map(Observation::mac).filter(m -> m != null)
                .map(m -> gateway.get(m.toLowerCase(Locale.ROOT))).filter(d -> d != null).findFirst();
        if (ha.isPresent()) {
            host = host.withHomeAssistant(ha.get().manufacturer(), ha.get().model(), ha.get().swVersion());
        }
        Classification c = rules.classify(host.signals());
        Map<Field, FieldResolver.Identification> fields = new java.util.EnumMap<>(FieldResolver.identify(host, c));
        Confidence overall = FieldResolver.overall(fields);
        Optional<Device> existing = devices.lockIdentity(scan.homeId(), host.mac(), host.primaryAddress());
        if (existing.isPresent()) {
            applyConfirmations(fields, existing.get());
        }
        Instant seenAt = group.stream().map(Observation::observedAt).max(Instant::compareTo).orElse(now);
        List<String> addresses = host.addresses().stream().limit(MAX_ADDRESSES).toList();
        Detected detected = new Detected(host.primaryAddress(), addresses, value(fields, Field.HOSTNAME),
                value(fields, Field.MANUFACTURER), value(fields, Field.MODEL), value(fields, Field.OS),
                c.category().name(), c.confidence() == null ? null : c.confidence().name(), overall.name(),
                explanation(c), c.rulesetVersion(), seenAt, scan.id());

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
        if (detected.hostname() != null && existing.map(Device::probableSameAs).isEmpty()) {
            // privacy MAC or second interface: probably a device already known under the same name;
            // only a suggestion, merged when the user confirms it (M19)
            devices.otherWithHostname(scan.homeId(), detected.hostname(), id).ifPresent(o -> devices.setProbableSameAs(id, o));
        }
        recordInterfacesAndAddresses(scan, id, mac, group, seenAt);
        devices.replaceIdentifications(scan.tenantId(), id, rows(fields, scan.id(), c.rulesetVersion(), now), null,
                now);
        devices.linkObservations(scan.id(), host.addresses(), id);
        images.adoptScanIcon(scan.id(), host.addresses(), id, now); // M23: icon declared by the device
        ports.linkToDevice(scan.id(), host.addresses(), id);
        ports.replaceProtocols(scan.tenantId(), id, scan.id(), DetectedProtocols.of(group, hostPorts, json));
    }

    /**
     * Interface (MAC) and address history of the device (M19): every address of the group with
     * the MAC it was seen with; IPv6 addresses with a random identifier not seen for
     * {@link #EPHEMERAL_RETENTION} are pruned, and the history keeps at most
     * {@link #MAX_ADDRESS_HISTORY} addresses (least recently seen dropped first).
     */
    private void recordInterfacesAndAddresses(Scan scan, UUID deviceId, String mac, List<Observation> group,
            Instant seenAt) {
        Set<String> macs = new java.util.LinkedHashSet<>();
        if (mac != null) {
            macs.add(mac);
        }
        group.stream().map(Observation::mac).filter(m -> m != null).map(m -> m.toLowerCase(Locale.ROOT))
                .forEach(macs::add);
        for (String m : macs) {
            boolean randomized = HostEvidence.locallyAdministered(m);
            String vendor = randomized ? null : oui.organizationOf(m).orElse(null);
            String iface = group.stream().filter(o -> m.equalsIgnoreCase(o.mac()) && o.iface() != null)
                    .map(Observation::iface).findFirst()
                    .orElse(group.stream().map(Observation::iface).filter(i -> i != null).findFirst().orElse(null));
            devices.upsertInterface(scan.tenantId(), scan.homeId(), deviceId, m, randomized, vendor,
                    iface == null || iface.length() > 64 ? null : iface, seenAt, scan.id());
        }
        Map<String, String> macByAddress = new LinkedHashMap<>();
        for (Observation o : group) {
            if (Addresses.classify(o.ip()).isEmpty()) {
                continue;
            }
            String m = o.mac() != null ? o.mac().toLowerCase(Locale.ROOT) : null;
            if (m == null) {
                m = Addresses.eui64Mac(o.ip()).filter(macs::contains).orElse(null);
            }
            String finalMac = m;
            macByAddress.merge(o.ip(), finalMac == null ? "" : finalMac, (a, b) -> a.isEmpty() ? b : a);
            if (o.mac() != null) {
                // recorded only: never a scan target, never a device's current address (ADR-075)
                for (String global : globalIpv6(o)) {
                    macByAddress.putIfAbsent(global, o.mac().toLowerCase(Locale.ROOT));
                }
            }
        }
        macByAddress.forEach((ip, m) -> devices.upsertAddress(scan.tenantId(), deviceId, ip, m.isEmpty() ? null : m,
                seenAt, scan.id()));
        List<DeviceRepository.Address> history = devices.addresses(deviceId);
        Instant cutoff = seenAt.minus(EPHEMERAL_RETENTION);
        List<UUID> prune = new ArrayList<>();
        int kept = 0;
        for (DeviceRepository.Address a : history) { // most recently seen first
            boolean ephemeral = Addresses.classify(a.address()).map(Addresses.Info::ephemeral).orElse(false);
            if ((ephemeral && a.lastSeenAt().isBefore(cutoff)) || kept >= MAX_ADDRESS_HISTORY) {
                prune.add(a.id());
            } else {
                kept++;
            }
        }
        devices.deleteAddresses(prune);
    }

    private PortSeen portSeen(StoredPort p) {
        PortRepository.Service s = p.service();
        return s == null ? new PortSeen(p.protocol(), p.port(), null, null, null, null)
                : new PortSeen(p.protocol(), p.port(), s.name(), s.product(), s.status(),
                        s.evidenceJson() == null ? null
                        : json.readValue(s.evidenceJson(), new TypeReference<Map<String, Object>>() {
                        }));
    }

    /** Valid global unicast IPv6 literals of {@link #GLOBAL_IPV6_DETAIL}; anything else is ignored. */
    List<String> globalIpv6(Observation o) {
        if (o.details() == null || !o.details().contains(GLOBAL_IPV6_DETAIL)) {
            return List.of();
        }
        Object value;
        try {
            value = details(o).get(GLOBAL_IPV6_DETAIL);
        } catch (RuntimeException e) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        return list.stream().filter(String.class::isInstance).map(String.class::cast)
                .map(Addresses::classify).flatMap(Optional::stream)
                .filter(i -> i.family() == 6 && i.scope() == Addresses.Scope.GLOBAL).map(Addresses.Info::address)
                .distinct().limit(MAX_GLOBAL_IPV6_PER_OBSERVATION).toList();
    }

    private Map<String, Object> details(Observation o) {
        return o.details() == null ? null : json.readValue(o.details(), new TypeReference<Map<String, Object>>() {
        });
    }

    /**
     * Values confirmed by the user and the manual category win over the scanned ones (M20): a
     * scan never overwrites them; a different scanned value is kept as a conflict.
     */
    void applyConfirmations(Map<Field, FieldResolver.Identification> fields, Device device) {
        for (Map.Entry<String, String> e : devices.confirmations(device.id()).entrySet()) {
            Field f = Field.valueOf(e.getKey());
            fields.put(f, FieldResolver.confirmed(f, e.getValue(), fields.get(f)));
        }
        if (device.manualCategory() != null) {
            fields.put(Field.DEVICE_TYPE,
                    FieldResolver.confirmed(Field.DEVICE_TYPE, device.manualCategory(), fields.get(Field.DEVICE_TYPE)));
        }
    }

    List<Identification> rows(Map<Field, FieldResolver.Identification> fields, UUID scanId, String ruleset,
            Instant now) {
        return fields.values().stream()
                .map(f -> new Identification(f.field().name(), f.value(), f.confidence().name(),
                        json.writeValueAsString(f.sources()), f.conflict(), scanId, ruleset, now, f.status().name()))
                .toList();
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
