package com.shsc.devices.images;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.devices.images.DeviceImageRepository.ImageMeta;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;

/** Device images (M23, docs/05-API.md): metadata, bytes, upload and removal of the user's photo. */
@RestController
public class DeviceImageController {

    /**
     * {@code source} DEVICE (icon declared by the device, origin UPNP) or USER (photo uploaded,
     * origin UPLOAD); {@code shown}: the image displayed for the device (USER first).
     */
    public record ImageResponse(UUID deviceId, String source, String origin, String contentType, Integer width,
            Integer height, Instant updatedAt, boolean shown) {
    }

    private final DeviceImageService service;

    public DeviceImageController(DeviceImageService service) {
        this.service = service;
    }

    /** The image shown for each device of the home that has one (devices without: category icon). */
    @GetMapping("/api/v1/homes/{homeId}/device-images")
    public List<ImageResponse> home(@PathVariable UUID homeId) {
        return service.shownInHome(homeId).stream().map(m -> response(m, true)).toList();
    }

    @GetMapping("/api/v1/devices/{deviceId}/images")
    public List<ImageResponse> device(@PathVariable UUID deviceId) {
        return responses(service.ofDevice(deviceId));
    }

    /** Image bytes; served as an inert image (nosniff, sandboxed, no script can run). */
    @GetMapping("/api/v1/devices/{deviceId}/image")
    public ResponseEntity<byte[]> image(@PathVariable UUID deviceId,
            @RequestParam(required = false) String source) {
        if (source != null && !source.equals("DEVICE") && !source.equals("USER")) {
            throw ApiException.badRequest("INVALID_SOURCE", "source must be DEVICE or USER.");
        }
        DeviceImageRepository.Image image = service.image(deviceId, source).orElseThrow(ApiException::notFound);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(image.contentType()))
                .cacheControl(CacheControl.noCache().cachePrivate())
                .eTag('"' + image.sha256() + '"')
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Security-Policy", "default-src 'none'; sandbox")
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline")
                .body(image.data());
    }

    /** Body: the PNG or JPEG photo itself (at most 1 MB); it is shown instead of the device icon. */
    @PutMapping(path = "/api/v1/devices/{deviceId}/image", consumes = { MediaType.IMAGE_PNG_VALUE,
            MediaType.IMAGE_JPEG_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE })
    public List<ImageResponse> upload(@PathVariable UUID deviceId, @RequestBody byte[] data,
            HttpServletRequest http) {
        return responses(service.upload(deviceId, data, ClientInfo.from(http)));
    }

    /** Removes the user's photo; the device icon (if any) is shown again. */
    @DeleteMapping("/api/v1/devices/{deviceId}/image")
    public List<ImageResponse> remove(@PathVariable UUID deviceId, HttpServletRequest http) {
        return responses(service.removeUpload(deviceId, ClientInfo.from(http)));
    }

    private static List<ImageResponse> responses(List<ImageMeta> metas) {
        return java.util.stream.IntStream.range(0, metas.size()).mapToObj(i -> response(metas.get(i), i == 0))
                .toList();
    }

    private static ImageResponse response(ImageMeta m, boolean shown) {
        return new ImageResponse(m.deviceId(), m.source(), m.origin(), m.contentType(), m.width(), m.height(),
                m.updatedAt(), shown);
    }
}
