package com.shsc.devices.oui;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.oui.OuiRegistryParser.Entry;
import com.shsc.devices.oui.OuiRepository.RegistryStatus;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.web.ApiException;

/**
 * Synchronization of the IEEE registries (public CSV files, no account, no cost). Started only
 * by a platform administrator: every configured file is downloaded (HTTPS, size and time
 * limits) and parsed first; the registries are replaced in one transaction only if every file
 * was read correctly, so a failed download never leaves a half-empty table.
 */
@Service
public class OuiSyncService {

    private static final Logger LOG = LoggerFactory.getLogger(OuiSyncService.class);

    public record SyncResult(Map<String, Integer> entries, int skipped, List<RegistryStatus> registries) {
    }

    private final OuiRepository repository;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final TransactionTemplate tx;
    private final ShscProperties.Oui settings;
    private final Clock clock;

    public OuiSyncService(OuiRepository repository, AccessPolicy access, AuditLog audit, TransactionTemplate tx,
            ShscProperties properties, Clock clock) {
        this.repository = repository;
        this.access = access;
        this.audit = audit;
        this.tx = tx;
        this.settings = properties.oui();
        this.clock = clock;
    }

    public List<RegistryStatus> status() {
        access.require(Permissions.PLATFORM_ADMIN);
        return tx.execute(s -> repository.status());
    }

    /** Platform administrators only (403 for everybody else). */
    public SyncResult sync() {
        AuthenticatedUser user = access.require(Permissions.PLATFORM_ADMIN);
        try {
            SyncResult result = sync(settings.sources());
            audit.record(AuditEvent.of(AuditAction.OUI_REGISTRY_SYNCED).tenant(user.tenantId()).user(user.userId())
                    .detail("entries", result.entries()).detail("skipped", result.skipped()).build());
            return result;
        } catch (ApiException e) {
            audit.record(AuditEvent.of(AuditAction.OUI_REGISTRY_SYNCED).tenant(user.tenantId()).user(user.userId())
                    .failure(e.getCode()).build());
            throw e;
        }
    }

    SyncResult sync(List<URI> sources) {
        Map<String, List<Entry>> byRegistry = new LinkedHashMap<>();
        int skipped = 0;
        HttpClient client = HttpClient.newBuilder().connectTimeout(settings.timeout())
                .followRedirects(HttpClient.Redirect.NORMAL).build();
        for (URI source : sources) {
            OuiRegistryParser.Result parsed = parse(source, download(client, source));
            if (parsed.entries().isEmpty()) {
                throw failed("OUI_SOURCE_EMPTY", source);
            }
            skipped += parsed.skipped();
            parsed.entries().forEach(e -> byRegistry.computeIfAbsent(e.registry(), r -> new ArrayList<>()).add(e));
        }
        Instant now = clock.instant();
        tx.executeWithoutResult(s -> byRegistry.forEach((registry, entries) -> repository.replace(registry, entries, now)));
        Map<String, Integer> counts = new LinkedHashMap<>();
        byRegistry.forEach((registry, entries) -> counts.put(registry, entries.size()));
        LOG.info("OUI registries synchronized: {} ({} rows skipped)", counts, skipped);
        return new SyncResult(counts, skipped, tx.execute(s -> repository.status()));
    }

    private byte[] download(HttpClient client, URI source) {
        if (!allowed(source)) {
            throw failed("OUI_SOURCE_NOT_ALLOWED", source);
        }
        HttpRequest request = HttpRequest.newBuilder(source).timeout(settings.timeout())
                .header("User-Agent", "shsc-oui-sync/1.0").header("Accept", "text/csv").GET().build();
        try {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() != 200 || !allowed(response.uri())) {
                    throw failed("OUI_SOURCE_UNAVAILABLE", source);
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[64 * 1024];
                int n;
                while ((n = body.read(buffer)) > 0) {
                    if (out.size() + n > settings.maxBytes()) {
                        throw failed("OUI_SOURCE_TOO_LARGE", source);
                    }
                    out.write(buffer, 0, n);
                }
                return out.toByteArray();
            }
        } catch (IOException e) {
            throw failed("OUI_SOURCE_UNAVAILABLE", source);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw failed("OUI_SOURCE_UNAVAILABLE", source);
        }
    }

    private static OuiRegistryParser.Result parse(URI source, byte[] body) {
        try {
            return OuiRegistryParser.parse(new StringReader(new String(body, StandardCharsets.UTF_8)));
        } catch (IOException e) {
            throw failed("OUI_SOURCE_INVALID", source);
        }
    }

    /** HTTPS; plain HTTP only towards this machine (local mirror, tests). */
    private static boolean allowed(URI uri) {
        if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) {
            return true;
        }
        if (!"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            return false;
        }
        try {
            return InetAddress.getByName(uri.getHost()).isLoopbackAddress();
        } catch (IOException e) {
            return false;
        }
    }

    private static ApiException failed(String code, URI source) {
        LOG.warn("OUI synchronization failed: {} ({})", code, source);
        return new ApiException(HttpStatus.BAD_GATEWAY, code, "The IEEE registry could not be synchronized.",
                Map.of("source", source.toString()));
    }
}
