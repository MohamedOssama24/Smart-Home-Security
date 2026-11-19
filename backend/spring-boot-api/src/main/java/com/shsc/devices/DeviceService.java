package com.shsc.devices;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceRepository.CategoryChange;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.devices.DeviceRepository.Identification;
import com.shsc.devices.fingerprint.DeviceCategory;
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

/**
 * Device inventory for users: {@code device:read} on the home to read, {@code device:classify}
 * to set or clear the manual category (other tenants and homes outside the scopes: 404).
 */
@Service
public class DeviceService {

    public record DeviceDetail(Device device, List<Identification> identifications, List<CategoryChange> changes,
            Services services) {
    }

    /** Open ports, services and protocols of the last scan that scanned the ports of the device (M9). */
    public record Services(PortScan scan, List<StoredPort> ports, List<Protocol> protocols) {
    }

    private final DeviceRepository devices;
    private final PortRepository ports;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public DeviceService(DeviceRepository devices, PortRepository ports, HomeRepository homes, AccessPolicy access,
            AuditLog audit, Clock clock) {
        this.devices = devices;
        this.ports = ports;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
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
        return new DeviceDetail(device, devices.identifications(deviceId), devices.categoryChanges(deviceId),
                services(deviceId));
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
        return new DeviceDetail(devices.find(deviceId).orElseThrow(), devices.identifications(deviceId),
                devices.categoryChanges(deviceId), services(deviceId));
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
