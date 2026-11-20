package com.shsc.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Minimal browser-like HTTP client for tests: keeps cookies, sends the CSRF header taken
 * from the XSRF-TOKEN cookie (like Angular does) and comes from its own client IP
 * (X-Forwarded-For), so throttling of one test never affects another.
 */
public class ApiClient {

    public record Response(int status, Map<String, List<String>> headers, String body, JsonNode json) {

        public String text(String field) {
            JsonNode node = json == null ? null : json.get(field);
            return node == null || node.isNull() ? null : node.asString();
        }

        public Optional<String> header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .flatMap(e -> e.getValue().stream()).findFirst();
        }

        public List<String> setCookies() {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase("set-cookie"))
                    .flatMap(e -> e.getValue().stream()).toList();
        }

        public Optional<String> setCookie(String name) {
            return setCookies().stream().filter(c -> c.startsWith(name + "=")).findFirst();
        }
    }

    private final String base;
    private final JsonMapper json;
    private final HttpClient http = HttpClient.newHttpClient();
    private final Map<String, String> cookies = new LinkedHashMap<>();
    private String ip;
    private String bearer;
    private boolean sendCsrf = true;

    public ApiClient(String base, JsonMapper json) {
        this.base = base;
        this.json = json;
        ThreadLocalRandom r = ThreadLocalRandom.current();
        this.ip = "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + (1 + r.nextInt(254));
    }

    public ApiClient bearer(String token) {
        this.bearer = token;
        return this;
    }

    public ApiClient ip(String ip) {
        this.ip = ip;
        return this;
    }

    public ApiClient withoutCsrf() {
        this.sendCsrf = false;
        return this;
    }

    public String cookie(String name) {
        return cookies.get(name);
    }

    public void setCookie(String name, String value) {
        cookies.put(name, value);
    }

    public String ip() {
        return ip;
    }

    public Response get(String path) {
        return send("GET", path, null, Map.of());
    }

    public Response post(String path, Object body) {
        return send("POST", path, body, Map.of());
    }

    public Response put(String path, Object body) {
        return send("PUT", path, body, Map.of());
    }

    public Response patch(String path, Object body) {
        return send("PATCH", path, body, Map.of());
    }

    public Response delete(String path) {
        return send("DELETE", path, null, Map.of());
    }

    public Response send(String method, String path, Object body, Map<String, String> extraHeaders) {
        boolean authEndpoint = path.startsWith("/api/v1/auth/") && !"GET".equals(method);
        if (authEndpoint && sendCsrf && !cookies.containsKey("XSRF-TOKEN")) {
            send("GET", "/api/v1/auth/csrf", null, Map.of());
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .header("X-Forwarded-For", ip)
                .header("User-Agent", "shsc-tests");
        String payload = body == null ? null : (body instanceof String s ? s : json.writeValueAsString(body));
        request.method(method, payload == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(payload));
        if (payload != null) {
            request.header("Content-Type", "application/json");
        }
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        if (authEndpoint && sendCsrf && cookies.containsKey("XSRF-TOKEN")) {
            request.header("X-XSRF-TOKEN", cookies.get("XSRF-TOKEN"));
        }
        if (!cookies.isEmpty()) {
            request.header("Cookie", cookies.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("; ")));
        }
        extraHeaders.forEach(request::header);
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            storeCookies(response.headers().allValues("set-cookie"));
            String text = response.body();
            JsonNode node = null;
            String type = response.headers().firstValue("content-type").orElse("");
            if (text != null && !text.isBlank() && type.contains("json")) {
                node = json.readTree(text);
            }
            return new Response(response.statusCode(), response.headers().map(), text, node);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** Binary answer (M23 device images). */
    public record BinaryResponse(int status, Map<String, List<String>> headers, byte[] body) {
        public Optional<String> header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .flatMap(e -> e.getValue().stream()).findFirst();
        }
    }

    /** Sends raw bytes (null: no body) and returns the raw answer, bearer authentication only. */
    public BinaryResponse sendBytes(String method, String path, byte[] body, String contentType) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .header("X-Forwarded-For", ip)
                .header("User-Agent", "shsc-tests")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(body));
        if (contentType != null) {
            request.header("Content-Type", contentType);
        }
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        try {
            HttpResponse<byte[]> response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            return new BinaryResponse(response.statusCode(), response.headers().map(), response.body());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private void storeCookies(List<String> setCookies) {
        for (String header : setCookies) {
            String[] parts = header.split(";");
            String[] pair = parts[0].split("=", 2);
            String name = pair[0].trim();
            String value = pair.length > 1 ? pair[1].trim() : "";
            boolean expired = header.toLowerCase().contains("max-age=0") || value.isEmpty();
            if (expired) {
                cookies.remove(name);
            } else {
                cookies.put(name, value);
            }
        }
    }
}
