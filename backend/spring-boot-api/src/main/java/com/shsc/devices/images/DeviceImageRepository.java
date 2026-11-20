package com.shsc.devices.images;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Device images (M23): icons received with a scan and the images shown for each device. */
@Repository
public class DeviceImageRepository {

    /** Icon declared by a device, as received from the agent (already validated). */
    public record ScanIcon(String ip, String origin, ImageFormat.Info info, byte[] data, Instant observedAt) {
    }

    /** Metadata of an image; {@code source} DEVICE or USER. */
    public record ImageMeta(UUID deviceId, String source, String origin, String contentType, Integer width,
            Integer height, Instant updatedAt) {
    }

    public record Image(String source, String contentType, byte[] data, String sha256) {
    }

    private final JdbcClient jdbc;

    public DeviceImageRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** First copy wins: a repeated batch does not replace the icon. */
    public void insertScanIcon(UUID tenantId, UUID scanId, ScanIcon icon) {
        jdbc.sql("""
                INSERT INTO scan_device_icons (tenant_id, scan_id, ip, origin, content_type, data, width, height,
                    observed_at)
                VALUES (:tenant, :scan, CAST(:ip AS inet), :origin, :type, :data, :width, :height, :at)
                ON CONFLICT (scan_id, ip) DO NOTHING""")
                .param("tenant", tenantId).param("scan", scanId).param("ip", icon.ip()).param("origin", icon.origin())
                .param("type", icon.info().contentType()).param("data", icon.data())
                .param("width", icon.info().width()).param("height", icon.info().height())
                .param("at", Sql.ts(icon.observedAt())).update();
    }

    /**
     * The icon of the scan received from one of the addresses of the device becomes its DEVICE
     * image; the user's photo (USER) is never touched. The scan copy is then removed.
     */
    public void adoptScanIcon(UUID scanId, List<String> addresses, UUID deviceId, Instant now) {
        if (addresses.isEmpty()) {
            return;
        }
        String ips = "{" + String.join(",", addresses) + "}";
        jdbc.sql("""
                INSERT INTO device_images (tenant_id, device_id, source, origin, content_type, data, sha256, width,
                    height, scan_id, updated_at)
                SELECT tenant_id, :device, 'DEVICE', origin, content_type, data, encode(sha256(data), 'hex'), width,
                    height, scan_id, :now
                FROM scan_device_icons
                WHERE scan_id = :scan AND host(ip) = ANY (CAST(:ips AS text[]))
                ORDER BY observed_at DESC LIMIT 1
                ON CONFLICT (device_id, source) DO UPDATE SET origin = EXCLUDED.origin,
                    content_type = EXCLUDED.content_type, data = EXCLUDED.data, width = EXCLUDED.width,
                    height = EXCLUDED.height, scan_id = EXCLUDED.scan_id,
                    updated_at = CASE WHEN device_images.sha256 = EXCLUDED.sha256 THEN device_images.updated_at
                                      ELSE EXCLUDED.updated_at END,
                    sha256 = EXCLUDED.sha256""")
                .param("device", deviceId).param("scan", scanId).param("ips", ips).param("now", Sql.ts(now))
                .update();
        jdbc.sql("DELETE FROM scan_device_icons WHERE scan_id = :scan AND host(ip) = ANY (CAST(:ips AS text[]))")
                .param("scan", scanId).param("ips", ips).update();
    }

    /** The image shown for each device of the home: the user's photo first, then the device icon. */
    public List<ImageMeta> shownInHome(UUID homeId) {
        return jdbc.sql("""
                SELECT DISTINCT ON (i.device_id) i.device_id, i.source, i.origin, i.content_type, i.width, i.height,
                    i.updated_at
                FROM device_images i JOIN devices d ON d.id = i.device_id
                WHERE d.home_id = :home
                ORDER BY i.device_id, (i.source = 'USER') DESC""")
                .param("home", homeId).query(DeviceImageRepository::meta).list();
    }

    public List<ImageMeta> ofDevice(UUID deviceId) {
        return jdbc.sql("""
                SELECT device_id, source, origin, content_type, width, height, updated_at
                FROM device_images WHERE device_id = :device ORDER BY (source = 'USER') DESC""")
                .param("device", deviceId).query(DeviceImageRepository::meta).list();
    }

    /** {@code source} null: the image shown (user's photo first). */
    public Optional<Image> image(UUID deviceId, String source) {
        return jdbc.sql("""
                SELECT source, content_type, data, sha256 FROM device_images
                WHERE device_id = :device AND (CAST(:source AS text) IS NULL OR source = :source)
                ORDER BY (source = 'USER') DESC LIMIT 1""")
                .param("device", deviceId).param("source", source)
                .query((rs, n) -> new Image(rs.getString("source"), rs.getString("content_type"),
                        rs.getBytes("data"), rs.getString("sha256")))
                .optional();
    }

    public void upsertUserImage(UUID tenantId, UUID deviceId, ImageFormat.Info info, byte[] data, String sha256,
            UUID userId, Instant now) {
        jdbc.sql("""
                INSERT INTO device_images (tenant_id, device_id, source, origin, content_type, data, sha256, width,
                    height, uploaded_by, updated_at)
                VALUES (:tenant, :device, 'USER', 'UPLOAD', :type, :data, :sha, :width, :height, :user, :now)
                ON CONFLICT (device_id, source) DO UPDATE SET content_type = EXCLUDED.content_type,
                    data = EXCLUDED.data, sha256 = EXCLUDED.sha256, width = EXCLUDED.width,
                    height = EXCLUDED.height, uploaded_by = EXCLUDED.uploaded_by, updated_at = EXCLUDED.updated_at""")
                .param("tenant", tenantId).param("device", deviceId).param("type", info.contentType())
                .param("data", data).param("sha", sha256).param("width", info.width()).param("height", info.height())
                .param("user", userId).param("now", Sql.ts(now)).update();
    }

    public boolean deleteUserImage(UUID deviceId) {
        return jdbc.sql("DELETE FROM device_images WHERE device_id = :device AND source = 'USER'")
                .param("device", deviceId).update() > 0;
    }

    private static ImageMeta meta(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
        return new ImageMeta(rs.getObject("device_id", UUID.class), rs.getString("source"), rs.getString("origin"),
                rs.getString("content_type"), (Integer) rs.getObject("width"), (Integer) rs.getObject("height"),
                rs.getObject("updated_at", java.time.OffsetDateTime.class).toInstant());
    }
}
