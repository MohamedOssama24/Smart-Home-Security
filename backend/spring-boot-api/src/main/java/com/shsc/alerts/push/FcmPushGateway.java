package com.shsc.alerts.push;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Firebase Cloud Messaging, HTTP v1 API (docs/23-MOBILE-APP.md §4), without the Google SDK: the
 * service-account key signs an RS256 assertion exchanged for a short OAuth access token (scope
 * {@code firebase.messaging}), cached until shortly before it expires.
 * <p>
 * Disabled unless both {@code shsc.push.fcm.project-id} and {@code shsc.push.fcm.credentials-file}
 * are set: without a Firebase project of the owner nothing is sent and no PUSH delivery is created.
 * Neither the device token nor the notification text is logged.
 */
@Component
public class FcmPushGateway implements PushGateway {

    private static final Logger LOG = LoggerFactory.getLogger(FcmPushGateway.class);
    static final String SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private record Credentials(String clientEmail, PrivateKey key, URI tokenUri) {
    }

    private record AccessToken(String value, Instant expiresAt) {
    }

    private final JsonMapper json;
    private final Clock clock;
    private final String projectId;
    private final URI endpoint;
    private final Credentials credentials;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private AccessToken token;

    public FcmPushGateway(JsonMapper json, Clock clock,
            @Value("${shsc.push.fcm.project-id:}") String projectId,
            @Value("${shsc.push.fcm.credentials-file:}") String credentialsFile,
            @Value("${shsc.push.fcm.endpoint:https://fcm.googleapis.com}") URI endpoint) {
        this.json = json;
        this.clock = clock;
        this.projectId = projectId == null ? "" : projectId.trim();
        this.endpoint = endpoint;
        this.credentials = this.projectId.isEmpty() || credentialsFile == null || credentialsFile.isBlank() ? null
                : load(Path.of(credentialsFile.trim()));
        LOG.info("Push notifications (FCM): {}", enabled() ? "enabled" : "disabled (not configured)");
    }

    @Override
    public boolean enabled() {
        return credentials != null;
    }

    @Override
    public Result send(String deviceToken, String title, String body, Map<String, String> data) {
        if (!enabled()) {
            return Result.FAILED;
        }
        try {
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("token", deviceToken);
            message.put("notification", Map.of("title", title, "body", body));
            message.put("data", data);
            message.put("android", Map.of("priority", "HIGH"));
            HttpRequest request = HttpRequest.newBuilder(endpoint.resolve("/v1/projects/"
                            + URLEncoder.encode(projectId, StandardCharsets.UTF_8) + "/messages:send"))
                    .timeout(TIMEOUT)
                    .header("Authorization", "Bearer " + accessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("message", message))))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status / 100 == 2) {
                return Result.SENT;
            }
            if (status == 401) {
                synchronized (this) {
                    token = null; // fetched again at the next attempt
                }
            }
            String code = errorCode(response.body());
            LOG.warn("FCM send failed: HTTP {} {}", status, code);
            // an unknown or malformed registration token will never work again
            return status == 404 || "UNREGISTERED".equals(code) || ("INVALID_ARGUMENT".equals(code) && status == 400)
                    ? Result.INVALID_TOKEN : Result.FAILED;
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            LOG.warn("FCM send failed: {}", e.getClass().getSimpleName());
            return Result.FAILED;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.FAILED;
        }
    }

    /** OAuth 2.0 JWT bearer grant (RFC 7523) with the service-account key. */
    private synchronized String accessToken() throws IOException, InterruptedException, GeneralSecurityException {
        Instant now = clock.instant();
        if (token != null && now.isBefore(token.expiresAt().minusSeconds(60))) {
            return token.value();
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", credentials.clientEmail());
        claims.put("scope", SCOPE);
        claims.put("aud", credentials.tokenUri().toString());
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.getEpochSecond() + 3600);
        String unsigned = b64(json.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT"))) + "."
                + b64(json.writeValueAsBytes(claims));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(credentials.key());
        signer.update(unsigned.getBytes(StandardCharsets.US_ASCII));
        String assertion = unsigned + "." + b64(signer.sign());
        String form = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer",
                StandardCharsets.UTF_8) + "&assertion=" + assertion;
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(credentials.tokenUri()).timeout(TIMEOUT)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("OAuth token request failed: HTTP " + response.statusCode());
        }
        JsonNode body = json.readTree(response.body());
        String value = body.path("access_token").asString();
        if (value == null || value.isBlank()) {
            throw new IOException("OAuth token response without access_token");
        }
        token = new AccessToken(value, now.plusSeconds(body.path("expires_in").asLong(3600)));
        return value;
    }

    private String errorCode(String body) {
        try {
            JsonNode error = json.readTree(body).path("error");
            for (JsonNode detail : error.path("details")) {
                if (detail.has("errorCode")) {
                    return detail.path("errorCode").asString();
                }
            }
            return error.path("status").asString("");
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Service-account JSON downloaded by the owner from the Firebase console. */
    private Credentials load(Path file) {
        try {
            JsonNode node = json.readTree(Files.readString(file));
            String pem = node.path("private_key").asString().replaceAll("-----[A-Z ]+-----", "")
                    .replaceAll("\\s", "");
            PrivateKey key = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
            URI tokenUri = URI.create(node.path("token_uri").asString("https://oauth2.googleapis.com/token"));
            if (!"https".equals(tokenUri.getScheme()) && !"localhost".equals(tokenUri.getHost())
                    && !"127.0.0.1".equals(tokenUri.getHost())) {
                throw new IllegalStateException("token_uri must use HTTPS");
            }
            return new Credentials(node.path("client_email").asString(), key, tokenUri);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid FCM service-account file: " + e.getClass().getSimpleName(), e);
        }
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
