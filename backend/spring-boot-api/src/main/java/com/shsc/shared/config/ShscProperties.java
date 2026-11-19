package com.shsc.shared.config;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/** Typed view of the {@code shsc.*} configuration (all values come from environment variables). */
@Validated
@ConfigurationProperties("shsc")
public record ShscProperties(
        @NotNull URI publicBaseUrl,
        @Valid @NotNull Mail mail,
        @Valid @NotNull Security security,
        @Valid @NotNull Agent agent,
        @Valid @NotNull Scans scans,
        @Valid @NotNull Oui oui,
        @Valid @NotNull Vulnerabilities vulnerabilities) {

    public record Mail(@NotBlank String from) {
    }

    public record Security(
            @Valid @NotNull Jwt jwt,
            @Valid @NotNull Session session,
            @Valid @NotNull Tokens tokens,
            @Valid @NotNull Throttle throttle,
            @Valid @NotNull Cors cors,
            @Valid @NotNull Maintenance maintenance) {
    }

    public record Jwt(@NotBlank String privateKey, @NotBlank String issuer, @NotBlank String audience,
            @NotNull Duration accessTokenTtl) {
    }

    public record Session(@NotNull Duration refreshTokenTtl, @NotNull Duration maxLifetime,
            @NotBlank String cookieName, boolean cookieSecure) {
    }

    public record Tokens(@NotNull Duration emailVerificationTtl, @NotNull Duration passwordResetTtl,
            @NotNull Duration invitationTtl) {
    }

    public record Throttle(@Positive int accountMaxFailures, @NotNull Duration accountBaseLock,
            @NotNull Duration accountMaxLock, @Positive int ipMaxFailures, @NotNull Duration ipLock,
            @NotNull Duration window, @Positive int mailRequestsPerWindow) {
    }

    public record Cors(List<String> allowedOrigins) {
        public Cors {
            allowedOrigins = allowedOrigins == null ? List.of()
                    : allowedOrigins.stream().map(String::trim).filter(s -> !s.isEmpty()).toList();
        }
    }

    public record Maintenance(@NotNull Duration purgeRetention, @NotNull Duration purgeInterval) {
    }

    public record Agent(@NotNull Duration enrollmentTokenTtl, @NotNull Duration accessTokenTtl,
            @NotNull Duration assertionMaxLifetime, @NotNull Duration clockSkew,
            @NotBlank String assertionAudience, @NotBlank String rotationAudience,
            @NotNull Duration heartbeatInterval) {
    }

    /** Manual scan workflow (docs/02-MANUAL-SCAN-WORKFLOW.md, docs/03-AGENT-PROTOCOL.md §6-§8). */
    public record Scans(@NotBlank String jobSigningKey, @NotNull Duration queueTtl, @NotNull Duration lease,
            @NotNull Duration maxDuration, @NotNull Duration lateUploadWindow, @NotNull Duration longPollMax,
            @NotNull Duration progressInterval) {
    }

    /**
     * IEEE registries (MA-L, MA-M, MA-S CSV files), downloaded only when a platform
     * administrator asks for it (docs/17-DEVICE-FINGERPRINTING.md §2).
     */
    public record Oui(@NotEmpty List<URI> sources, @Positive long maxBytes, @NotNull Duration timeout) {
    }

    /**
     * Public vulnerability feeds (NVD CVE API 2.0, CISA KEV, FIRST EPSS), downloaded only when a
     * platform administrator asks for it (docs/19-SECURITY-ANALYSIS.md §2). The NVD API key is
     * optional (free, raises the rate limit) and never logged.
     */
    public record Vulnerabilities(@NotNull URI nvdUrl, @NotNull URI kevUrl, @NotNull URI epssUrl, String nvdApiKey,
            @NotNull Duration nvdRequestDelay, @Positive long maxBytes, @NotNull Duration timeout,
            @Positive int maxPagesPerProduct) {
    }
}
