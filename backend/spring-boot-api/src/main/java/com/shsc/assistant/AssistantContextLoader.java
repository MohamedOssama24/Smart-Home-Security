package com.shsc.assistant;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

import com.shsc.assistant.AssistantFacts.Device;
import com.shsc.assistant.AssistantFacts.Finding;
import com.shsc.assistant.AssistantFacts.Score;
import com.shsc.homes.HomeRepository.Home;
import com.shsc.reports.ReportRepository;
import com.shsc.reports.ReportRepository.DeviceRow;
import com.shsc.reports.ReportRepository.FindingRow;
import com.shsc.shared.i18n.UiTexts;
import com.shsc.shared.persistence.Sql;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Reads the facts of one home with the queries of the PDF report (same data, same RLS) plus the
 * last risk snapshot. Must run inside a transaction of the tenant.
 */
@Component
class AssistantContextLoader {

    static final int MAX_FINDINGS = 100;
    static final int MAX_DEVICES = 150;
    private static final int MAX_TEXT = 160;

    private final ReportRepository reports;
    private final JdbcClient jdbc;
    private final UiTexts texts;
    private final JsonMapper json;

    AssistantContextLoader(ReportRepository reports, JdbcClient jdbc, UiTexts texts, JsonMapper json) {
        this.reports = reports;
        this.jdbc = jdbc;
        this.texts = texts;
        this.json = json;
    }

    AssistantFacts load(Home home, String locale) {
        Snapshot snapshot = jdbc.sql("""
                SELECT scan_id, computed_at, score, risk_level, rating, not_computed_reason, coverage, provisional
                FROM risk_snapshots WHERE home_id = :home ORDER BY computed_at DESC, id DESC LIMIT 1""")
                .param("home", home.id())
                .query((rs, n) -> new Snapshot(Sql.uuid(rs, "scan_id"), Sql.instant(rs, "computed_at"),
                        new Score("S1", (Integer) rs.getObject("score"), rs.getString("risk_level"),
                                rs.getString("rating"), rs.getString("not_computed_reason"),
                                rs.getBigDecimal("coverage") == null ? null
                                        : rs.getBigDecimal("coverage").doubleValue(),
                                rs.getBoolean("provisional"))))
                .optional().orElse(null);

        List<DeviceRow> deviceRows = reports.devices(home.id());
        List<FindingRow> findingRows = reports.findings(home.id());
        boolean truncated = deviceRows.size() > MAX_DEVICES || findingRows.size() > MAX_FINDINGS;

        List<Device> devices = new ArrayList<>();
        Map<String, String> deviceByIp = new HashMap<>();
        for (DeviceRow d : deviceRows.subList(0, Math.min(MAX_DEVICES, deviceRows.size()))) {
            String id = "D" + (devices.size() + 1);
            devices.add(new Device(id, clean(d.name()), d.ip(), d.category(), clean(d.manufacturer())));
            if (d.ip() != null) {
                deviceByIp.put(d.ip(), id);
            }
        }
        List<Finding> findings = new ArrayList<>();
        for (FindingRow f : findingRows.subList(0, Math.min(MAX_FINDINGS, findingRows.size()))) {
            Map<String, Object> params = params(f.paramsJson());
            String recommendation = f.recommendationKey() != null && texts.has(locale, f.recommendationKey())
                    ? texts.text(locale, f.recommendationKey(), params)
                    : null;
            findings.add(new Finding("F" + (findings.size() + 1), clean(texts.text(locale, f.titleKey(), params)),
                    clean(recommendation), f.severity(), f.status(), deviceByIp.get(f.deviceIp()),
                    clean(f.deviceName()), f.deviceIp()));
        }
        return new AssistantFacts(home.name(), snapshot == null ? null : snapshot.scanId(),
                snapshot == null ? null : snapshot.computedAt(), snapshot == null ? null : snapshot.score(),
                List.copyOf(findings), List.copyOf(devices), truncated);
    }

    /**
     * Control and format characters and links removed, length bounded: host names and banners come
     * from the LAN and may carry prompt injection. Answers can therefore never contain a link.
     */
    static String clean(String s) {
        if (s == null) {
            return null;
        }
        String t = s.replaceAll("[\\p{Cntrl}\\p{Cf}]", " ").replaceAll("(?i)(?:https?://|www\\.)\\S*", "")
                .replaceAll("\\s+", " ").strip();
        if (t.length() > MAX_TEXT) {
            t = t.substring(0, MAX_TEXT);
        }
        return t.isEmpty() ? null : t;
    }

    private Map<String, Object> params(String text) {
        return text == null ? Map.of() : json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }

    private record Snapshot(java.util.UUID scanId, java.time.Instant computedAt, Score score) {
    }
}
