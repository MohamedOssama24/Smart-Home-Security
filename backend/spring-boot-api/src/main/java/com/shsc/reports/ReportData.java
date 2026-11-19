package com.shsc.reports;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Everything a PDF report shows, already read from the database: the renderer depends only on
 * this (snapshot tests build it by hand). {@code score == null} with {@code notComputedReason}
 * after a DISCOVERY scan; {@code coverage == null} when the scan has no risk snapshot.
 */
public record ReportData(
        UUID reportId,
        String locale,
        String homeName,
        ZoneId zone,
        Instant generatedAt,
        String scanProfile,
        Instant scanCompletedAt,
        Integer score,
        String riskLevel,
        String rating,
        String notComputedReason,
        Double coverage,
        boolean provisional,
        int hostsDiscovered,
        int hostsAnalyzed,
        List<Finding> findings,
        List<Device> devices,
        String brandName) {

    /** Without white label (brandName null). */
    public ReportData(UUID reportId, String locale, String homeName, ZoneId zone, Instant generatedAt,
            String scanProfile, Instant scanCompletedAt, Integer score, String riskLevel, String rating,
            String notComputedReason, Double coverage, boolean provisional, int hostsDiscovered, int hostsAnalyzed,
            List<Finding> findings, List<Device> devices) {
        this(reportId, locale, homeName, zone, generatedAt, scanProfile, scanCompletedAt, score, riskLevel, rating,
                notComputedReason, coverage, provisional, hostsDiscovered, hostsAnalyzed, findings, devices, null);
    }

    /** Texts are dashboard i18n keys with their parameters. */
    public record Finding(String titleKey, String recommendationKey, Map<String, Object> params, String severity,
            String type, String status, String deviceName, String deviceIp) {
    }

    public record Device(String name, String ip, String category, String manufacturer) {
    }
}
