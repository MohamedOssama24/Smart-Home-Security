package com.shsc.vulnintel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Downloads one public feed document: HTTPS only (plain HTTP only towards this machine, for a
 * local mirror and the tests), size and time limits, redirects only to allowed addresses.
 * Header values (the optional NVD API key) are never logged.
 */
final class FeedDownloader {

    /** Download failure; the code is stored in the feed status. */
    static final class FeedException extends RuntimeException {
        private final String code;

        FeedException(String code) {
            super(code);
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    private final HttpClient client;
    private final Duration timeout;
    private final long maxBytes;

    FeedDownloader(Duration timeout, long maxBytes) {
        this.client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.timeout = timeout;
        this.maxBytes = maxBytes;
    }

    byte[] get(URI uri, Map<String, String> headers, String feed) {
        if (!allowed(uri)) {
            throw new FeedException(feed + "_SOURCE_NOT_ALLOWED");
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("User-Agent", "shsc-vuln-sync/1.0").header("Accept", "application/json").GET();
        headers.forEach(request::header);
        try {
            HttpResponse<InputStream> response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() != 200 || !allowed(response.uri())) {
                    throw new FeedException(feed + "_UNAVAILABLE");
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[64 * 1024];
                int n;
                while ((n = body.read(buffer)) > 0) {
                    if (out.size() + n > maxBytes) {
                        throw new FeedException(feed + "_TOO_LARGE");
                    }
                    out.write(buffer, 0, n);
                }
                return out.toByteArray();
            }
        } catch (IOException e) {
            throw new FeedException(feed + "_UNAVAILABLE");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FeedException(feed + "_INTERRUPTED");
        }
    }

    /** HTTPS; plain HTTP only towards this machine (local mirror, tests). */
    static boolean allowed(URI uri) {
        if (uri.getHost() == null) {
            return false;
        }
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return true;
        }
        if (!"http".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }
        try {
            return InetAddress.getByName(uri.getHost()).isLoopbackAddress();
        } catch (IOException e) {
            return false;
        }
    }
}
