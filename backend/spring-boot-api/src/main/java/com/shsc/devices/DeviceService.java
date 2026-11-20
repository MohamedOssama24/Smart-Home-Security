package com.shsc.devices;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceRepository.Address;
import com.shsc.devices.DeviceRepository.CategoryChange;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.devices.DeviceRepository.Identification;
import com.shsc.devices.DeviceRepository.IdentificationChange;
import com.shsc.devices.DeviceRepository.Interface;
import com.shsc.devices.fingerprint.DeviceCategory;
import com.shsc.devices.fingerprint.FieldResolver;
import com.shsc.devices.fingerprint.FieldResolver.Field;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.scans.PortRepository;
import com.shsc.scans.PortRepository.PortScan;
import com.shsc.scans.PortRepository.Protocol;
import com.shsc.scans.PortRepository.StoredPort;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Device inventory for users: {@code device:read} on the home to read, {@code device:classify}
 * to set or clear the manual category (other tenants and homes outside the scopes: 404).
 */
@Service
public class DeviceService {

    public record DeviceDetail(Device device, List<Identification> identifications, List<CategoryChange> changes,
            Services services, List<Interface> interfaces, List<Address> addressHistory,
            List<IdentificationChange> identificationHistory) {
    }

    /** Open ports, services and protocols of the last scan that scanned the ports of the device (M9). */
    public record Services(PortScan scan, List<StoredPort> ports, List<Protocol> protocols) {
    }

    /** Fields the user can confirm or correct (M20); the others are observed or have their own endpoint. */
    static final Set<String> CONFIRMABLE = Set.of("MANUFACTURER", "MODEL", "PRODUCT_CODE", "FIRMWARE", "CPE", "OS");
    private static final Pattern CPE = Pattern.compile("^cpe:2\\.3:[aho](:[^:\\s]+){10}$");
    private static final int MAX_CUSTOM_NAME = 100;

    private final DeviceRepository devices;
    private final PortRepository ports;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;
    private final JsonMapper json;

    public DeviceService(DeviceRepository devices, PortRepository ports, HomeRepository homes, AccessPolicy access,
            AuditLog audit, Clock clock, JsonMapper json) {
        this.devices = devices;
        this.ports = ports;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
        this.json = json;
    }

    /**
     * The user confirms or corrects a field (M20): the value becomes VERIFIED (source USER) and
     * later scans keep it; a different scanned value is shown as a conflict. {@code value} null
     * removes the confirmation: the scanned value applies again (PROBABLE until the next scan).
     */
    @Transactional
    public DeviceDetail confirm(UUID deviceId, String field, String value, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        String f = field == null ? "" : field.trim().toUpperCase(Locale.ROOT);
        if (!CONFIRMABLE.contains(f)) {
            throw ApiException.badRequest("INVALID_FIELD", "This field cannot be confirmed.");
        }
        String v = value == null ? null : clean(value, 255);
        if (value != null && v == null) {
            throw ApiException.badRequest("INVALID_VALUE", "Empty value.");
        }
        if (v != null && f.equals("OS")) {
            v = parseOs(v);
        }
        if (v != null && f.equals("CPE") && !CPE.matcher(v).matches()) {
            throw ApiException.badRequest("INVALID_CPE", "Not a CPE 2.3 formatted string.");
        }
        Instant now = clock.instant();
        String previous = devices.confirmations(deviceId).get(f);
        if (Objects.equals(previous, v)) {
            return detailOf(device);
        }
        devices.setConfirmation(device.tenantId(), deviceId, f, v, user.userId(), now);
        List<Identification> rows = new ArrayList<>();
        Identification current = null;
        for (Identification i : devices.identifications(deviceId)) {
            if (i.field().equals(f)) {
                current = i;
            } else {
                rows.add(i);
            }
        }
        Identification updated = v != null ? confirmedRow(f, v, current, device, now) : unconfirmedRow(current, now);
        if (updated != null) {
            rows.add(updated);
        }
        devices.replaceIdentifications(device.tenantId(), deviceId, rows, user.userId(), now);
        if (updated != null) {
            devices.applyConfirmedColumns(deviceId, f.equals("MANUFACTURER") ? updated.value() : null,
                    f.equals("MODEL") ? updated.value() : null, f.equals("OS") ? updated.value() : null);
        }
        audit.record(AuditEvent.of(AuditAction.DEVICE_IDENTITY_CONFIRMED).tenant(device.tenantId())
                .user(user.userId()).client(client).target("DEVICE", deviceId).detail("homeId", device.homeId())
                .detail("field", f).detail("confirmed", v != null).build());
        return detailOf(devices.find(deviceId).orElseThrow());
    }

    /** Name given by the user (M20), shown instead of the host name; null clears it. Never changed by scans. */
    @Transactional
    public DeviceDetail rename(UUID deviceId, String name, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        String v = name == null ? null : clean(name, MAX_CUSTOM_NAME);
        if (name != null && v == null) {
            throw ApiException.badRequest("INVALID_NAME", "Empty name.");
        }
        if (!Objects.equals(v, device.customName())) {
            devices.setCustomName(deviceId, v);
            audit.record(AuditEvent.of(AuditAction.DEVICE_RENAMED).tenant(device.tenantId()).user(user.userId())
                    .client(client).target("DEVICE", deviceId).detail("homeId", device.homeId()).build());
        }
        return detailOf(devices.find(deviceId).orElseThrow());
    }

    private Identification confirmedRow(String field, String value, Identification current, Device device,
            Instant now) {
        List<Map<String, Object>> sources = new ArrayList<>();
        sources.add(source(FieldResolver.SOURCE_USER, value));
        boolean conflict = false;
        if (current != null) {
            Field f = Field.valueOf(field);
            boolean agrees = FieldResolver.key(f, current.value()).equals(FieldResolver.key(f, value));
            conflict = !agrees;
            for (Map<String, Object> s : sources(current)) {
                if (!FieldResolver.SOURCE_USER.equals(s.get("source")) && Boolean.TRUE.equals(s.get("agrees"))) {
                    Map<String, Object> copy = new LinkedHashMap<>(s);
                    copy.put("agrees", agrees);
                    sources.add(copy);
                }
            }
        }
        return new Identification(field, value, "HIGH", json.writeValueAsString(sources.subList(0,
                Math.min(12, sources.size()))), conflict, current != null ? current.scanId() : device.lastScanId(),
                current != null ? current.rulesetVersion() : device.rulesetVersion(), now, "VERIFIED");
    }

    /** Without the user's value: the scanned one, PROBABLE until the next scan recomputes it. */
    private Identification unconfirmedRow(Identification current, Instant now) {
        if (current == null) {
            return null;
        }
        List<Map<String, Object>> scanned = sources(current).stream()
                .filter(s -> !FieldResolver.SOURCE_USER.equals(s.get("source"))).toList();
        if (scanned.isEmpty() || !(scanned.get(0).get("value") instanceof String v)) {
            return null;
        }
        List<Map<String, Object>> sources = scanned.stream().map(s -> {
            Map<String, Object> copy = new LinkedHashMap<>(s);
            copy.put("agrees", v.equals(s.get("value")));
            return (Map<String, Object>) copy;
        }).toList();
        return new Identification(current.field(), v, "MEDIUM", json.writeValueAsString(sources), false,
                current.scanId(), current.rulesetVersion(), now, "PROBABLE");
    }

    private List<Map<String, Object>> sources(Identification i) {
        return json.readValue(i.sourcesJson(), new TypeReference<List<Map<String, Object>>>() {
        });
    }

    private static Map<String, Object> source(String source, String value) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("source", source);
        s.put("value", value);
        s.put("reliability", "H");
        s.put("agrees", true);
        s.put("origin", source);
        s.put("declared", true);
        return s;
    }

    /** Trimmed, control characters removed, at most {@code max} characters; null when empty. */
    static String clean(String value, int max) {
        String v = value.replaceAll("\\p{Cntrl}", "").strip();
        if (v.isEmpty()) {
            return null;
        }
        return v.length() <= max ? v : v.substring(0, max);
    }

    private static String parseOs(String os) {
        try {
            return FieldResolver.Os.valueOf(os.trim().toUpperCase(Locale.ROOT)).name();
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("INVALID_OS", "Unknown operating system.");
        }
    }

    @Transactional(readOnly = true)
    public List<Device> list(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.DEVICE_READ, homeId);
        return devices.forHome(homeId);
    }

    @Transactional(readOnly = true)
    public DeviceDetail detail(UUID deviceId) {
        Device device = devices.find(deviceId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.DEVICE_READ, device.homeId());
        return detailOf(device);
    }

    /** Sets the manual category, or clears it with null (the detected one applies again). */
    @Transactional
    public DeviceDetail classify(UUID deviceId, String category, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        String value = category == null ? null : parse(category);
        if (!Objects.equals(value, device.manualCategory())) {
            Instant now = clock.instant();
            devices.setManualCategory(deviceId, value, user.userId(), now);
            devices.insertCategoryChange(device.tenantId(), deviceId, "MANUAL", device.manualCategory(), value, null,
                    user.userId(), now);
            audit.record(AuditEvent.of(AuditAction.DEVICE_CATEGORY_CHANGED).tenant(device.tenantId())
                    .user(user.userId()).client(client).target("DEVICE", deviceId).detail("homeId", device.homeId())
                    .detail("old", device.manualCategory() == null ? "-" : device.manualCategory())
                    .detail("new", value == null ? "-" : value).build());
        }
        return detailOf(devices.find(deviceId).orElseThrow());
    }

    /**
     * The user confirms that {@code sourceId} is the same physical device as {@code targetId}
     * (second interface, privacy MAC): interfaces, address history and findings move to the
     * target and the source is removed (M19, ADR-074). Never automatic.
     */
    @Transactional
    public DeviceDetail merge(UUID sourceId, UUID targetId, ClientInfo client) {
        if (sourceId.equals(targetId)) {
            throw ApiException.badRequest("SAME_DEVICE", "A device cannot be merged with itself.");
        }
        // lock in a fixed order: two opposite merges cannot deadlock
        boolean sourceFirst = sourceId.compareTo(targetId) < 0;
        Optional<Device> first = devices.lock(sourceFirst ? sourceId : targetId);
        Optional<Device> second = devices.lock(sourceFirst ? targetId : sourceId);
        Device source = (sourceFirst ? first : second).orElseThrow(ApiException::notFound);
        Device target = (sourceFirst ? second : first).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, source.homeId());
        if (!source.homeId().equals(target.homeId())) {
            throw ApiException.notFound();
        }
        devices.merge(sourceId, targetId);
        audit.record(AuditEvent.of(AuditAction.DEVICE_MERGED).tenant(target.tenantId()).user(user.userId())
                .client(client).target("DEVICE", targetId).detail("homeId", target.homeId())
                .detail("mergedDeviceId", sourceId).detail("mergedMac", source.mac() == null ? "-" : source.mac())
                .build());
        return detailOf(devices.find(targetId).orElseThrow());
    }

    /** The user says the two devices are different: the "probably the same device" hint goes away for good. */
    @Transactional
    public DeviceDetail dismissSameAs(UUID deviceId, UUID otherId, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        Device other = devices.find(otherId)
                .filter(o -> o.homeId().equals(device.homeId()) && !o.id().equals(deviceId))
                .orElseThrow(ApiException::notFound);
        devices.dismissSameAs(deviceId, other.id());
        audit.record(AuditEvent.of(AuditAction.DEVICE_SAME_AS_DISMISSED).tenant(device.tenantId())
                .user(user.userId()).client(client).target("DEVICE", deviceId).detail("homeId", device.homeId())
                .detail("otherDeviceId", other.id()).build());
        return detailOf(devices.find(deviceId).orElseThrow());
    }

    private DeviceDetail detailOf(Device device) {
        UUID id = device.id();
        return new DeviceDetail(device, devices.identifications(id), devices.categoryChanges(id), services(id),
                devices.interfaces(id), devices.addresses(id), devices.identificationHistory(id));
    }

    private Services services(UUID deviceId) {
        return ports.lastPortScan(deviceId)
                .map(s -> new Services(s, ports.ofDevice(deviceId, s.scanId()), ports.protocols(deviceId, s.scanId())))
                .orElse(null);
    }

    private static String parse(String category) {
        try {
            return DeviceCategory.valueOf(category.trim()).name();
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("INVALID_CATEGORY", "Unknown device category.");
        }
    }
}
