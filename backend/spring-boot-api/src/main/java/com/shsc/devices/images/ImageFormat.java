package com.shsc.devices.images;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Optional;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

/**
 * Accepts only PNG and JPEG images (M23, ADR-077), recognized by their magic bytes, never by the
 * declared type or the file name. Only the header is read to know the size: the pixels are never
 * decoded, so a "decompression bomb" costs nothing. SVG, GIF, HTML and everything else is refused.
 */
public final class ImageFormat {

    public record Info(String contentType, int width, int height) {
    }

    private static final byte[] PNG = { (byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };

    static {
        ImageIO.setUseCache(false); // never a temporary file
    }

    private ImageFormat() {
    }

    public static Optional<Info> inspect(byte[] data, int maxBytes, int maxSide) {
        if (data == null || data.length == 0 || data.length > maxBytes) {
            return Optional.empty();
        }
        String type;
        String format;
        if (data.length > PNG.length && Arrays.equals(data, 0, PNG.length, PNG, 0, PNG.length)) {
            type = "image/png";
            format = "png";
        } else if (data.length > 3 && (data[0] & 0xff) == 0xff && (data[1] & 0xff) == 0xd8
                && (data[2] & 0xff) == 0xff) {
            type = "image/jpeg";
            format = "jpeg";
        } else {
            return Optional.empty();
        }
        try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(data))) {
            Iterator<ImageReader> readers = ImageIO.getImageReadersByFormatName(format);
            if (in == null || !readers.hasNext()) {
                return Optional.empty();
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(in, true, true);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                if (width < 1 || height < 1 || width > maxSide || height > maxSide) {
                    return Optional.empty();
                }
                return Optional.of(new Info(type, width, height));
            } finally {
                reader.dispose();
            }
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }
}
