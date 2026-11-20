package com.shsc.devices.images;

import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceRepository;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.devices.images.DeviceImageRepository.Image;
import com.shsc.devices.images.DeviceImageRepository.ImageMeta;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * Device images (M23, ADR-077): the icon the device declares about itself (UPnP, fetched by the
 * agent) and an optional photo uploaded by the user, which is shown first and never replaced by
 * a scan. Stored locally; PNG/JPEG only.
 */
@Service
public class DeviceImageService {

    /** Uploaded photos: at most 1 MB and 4096 px per side. */
    public static final int MAX_UPLOAD_BYTES = 1 << 20;
    public static final int MAX_UPLOAD_SIDE = 4096;

    private final DeviceRepository devices;
    private final DeviceImageRepository images;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public DeviceImageService(DeviceRepository devices, DeviceImageRepository images, AccessPolicy access,
            AuditLog audit, Clock clock) {
        this.devices = devices;
        this.images = images;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<ImageMeta> shownInHome(UUID homeId) {
        access.requireOnHome(Permissions.DEVICE_READ, homeId);
        return images.shownInHome(homeId);
    }

    @Transactional(readOnly = true)
    public List<ImageMeta> ofDevice(UUID deviceId) {
        Device device = devices.find(deviceId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.DEVICE_READ, device.homeId());
        return images.ofDevice(deviceId);
    }

    @Transactional(readOnly = true)
    public Optional<Image> image(UUID deviceId, String source) {
        Device device = devices.find(deviceId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.DEVICE_READ, device.homeId());
        return images.image(deviceId, source);
    }

    @Transactional
    public List<ImageMeta> upload(UUID deviceId, byte[] data, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        if (data != null && data.length > MAX_UPLOAD_BYTES) {
            throw ApiException.badRequest("IMAGE_TOO_LARGE", "The photo must not exceed 1 MB.");
        }
        ImageFormat.Info info = ImageFormat.inspect(data, MAX_UPLOAD_BYTES, MAX_UPLOAD_SIDE)
                .orElseThrow(() -> ApiException.badRequest("INVALID_IMAGE",
                        "Only PNG or JPEG photos up to 4096 pixels per side are accepted."));
        String sha = sha256Hex(data);
        images.upsertUserImage(device.tenantId(), deviceId, info, data, sha, user.userId(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.DEVICE_IMAGE_UPLOADED).tenant(device.tenantId()).user(user.userId())
                .client(client).target("DEVICE", deviceId).detail("homeId", device.homeId())
                .detail("contentType", info.contentType()).detail("bytes", data.length).build());
        return images.ofDevice(deviceId);
    }

    @Transactional
    public List<ImageMeta> removeUpload(UUID deviceId, ClientInfo client) {
        Device device = devices.lock(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.DEVICE_CLASSIFY, device.homeId());
        if (images.deleteUserImage(deviceId)) {
            audit.record(AuditEvent.of(AuditAction.DEVICE_IMAGE_REMOVED).tenant(device.tenantId())
                    .user(user.userId()).client(client).target("DEVICE", deviceId)
                    .detail("homeId", device.homeId()).build());
        }
        return images.ofDevice(deviceId);
    }

    static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(data));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
