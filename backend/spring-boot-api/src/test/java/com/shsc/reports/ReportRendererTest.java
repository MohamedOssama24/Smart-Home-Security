package com.shsc.reports;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.support.ResourceBundleMessageSource;

import com.shsc.findings.FindingRule;
import com.shsc.findings.FindingRules;
import com.shsc.reports.ReportData.Device;
import com.shsc.reports.ReportData.Finding;
import com.shsc.reports.ReportRenderer.Rendered;
import com.shsc.shared.i18n.UiTexts;

import tools.jackson.databind.json.JsonMapper;

/**
 * PDF report snapshots (Milestone 13): the text of the IT and EN reports of a fixed [MOCK] home is
 * compared with the reviewed snapshots in src/test/resources/reports; the same data gives the
 * same bytes. A changed layout or text makes the test fail: review the new text written in
 * target/report-snapshots and copy it over the snapshot if it is right.
 */
class ReportRendererTest {

    private static final UiTexts TEXTS = new UiTexts(JsonMapper.builder().build());
    private static final ReportRenderer RENDERER = new ReportRenderer(messages(), TEXTS);

    private static ResourceBundleMessageSource messages() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n/messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        source.setAlwaysUseMessageFormat(true); // as spring.messages.always-use-message-format
        return source;
    }

    static ReportData mockHome(String locale) {
        List<Finding> findings = List.of(
                new Finding("findings.rule.telnet-open.title", "findings.rule.telnet-open.recommendation",
                        Map.of("port", 23), "HIGH", "SUSPICIOUS_CONFIGURATION", "OPEN", "mock-router", "192.168.90.1"),
                new Finding("findings.rule.cve-version-match.title", "findings.rule.cve-version-match.recommendation",
                        Map.of("cve", "CVE-2099-3001", "product", "MOCK rtspd", "version", "1.0"), "CRITICAL",
                        "CONFIRMED_VULNERABILITY", "ACKNOWLEDGED", "mock-camera", "192.168.90.30"),
                new Finding("findings.rule.upnp-igd-enabled.title", "findings.rule.upnp-igd-enabled.recommendation",
                        Map.of(), "LOW", "SUSPICIOUS_CONFIGURATION", "ACCEPTED_RISK", "mock-router", "192.168.90.1"));
        List<Device> devices = new ArrayList<>(List.of(
                new Device("mock-router", "192.168.90.1", "ROUTER", "MOCK Networks"),
                new Device("mock-camera", "192.168.90.30", "IP_CAMERA", null),
                // a name the standard PDF font cannot encode and a very long one
                new Device("tv-☃-📺", "192.168.90.40", "SMART_TV", "MOCK ≤ TV"),
                new Device("a-very-long-hostname-without-spaces-that-does-not-fit-the-column.mock.example.test",
                        "192.168.90.41", "UNKNOWN_DEVICE", null)));
        return new ReportData(UUID.fromString("00000000-0000-7000-8000-000000000013"), locale, "Casa MOCK",
                ZoneId.of("Europe/Rome"), Instant.parse("2026-11-18T10:15:00Z"), "STANDARD",
                Instant.parse("2026-11-18T10:00:00Z"), 58, "HIGH", "POOR", null, 0.6, true, 4, 3, findings, devices);
    }

    @ParameterizedTest
    @ValueSource(strings = { "it", "en" })
    void reportTextMatchesTheReviewedSnapshot(String locale) throws IOException {
        Rendered rendered = RENDERER.render(mockHome(locale));
        assertThat(new String(rendered.pdf(), 0, 5, StandardCharsets.US_ASCII)).isEqualTo("%PDF-");
        String text = text(rendered.pdf());
        Path output = Path.of("target/report-snapshots/report-" + locale + ".pdf"); // to look at it
        Files.createDirectories(output.getParent());
        Files.write(output, rendered.pdf());

        Path expected = Path.of("src/test/resources/reports/report-" + locale + ".txt");
        if (!Files.exists(expected) || !Files.readString(expected).equals(text)) {
            Path actual = Path.of("target/report-snapshots/report-" + locale + ".txt");
            Files.writeString(actual, text);
            assertThat(text).as("snapshot changed: review %s", actual)
                    .isEqualTo(Files.exists(expected) ? Files.readString(expected) : "");
        }
        // same data, same bytes (fixed dates and document ID)
        assertThat(RENDERER.render(mockHome(locale)).pdf()).isEqualTo(rendered.pdf());
    }

    @Test
    void longReportsContinueOnNewPagesWithNumberedFooters() throws IOException {
        ReportData base = mockHome("en");
        List<Finding> many = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            many.add(new Finding("findings.rule.telnet-open.title", "findings.rule.telnet-open.recommendation",
                    Map.of("port", 1000 + i), "MEDIUM", "SUSPICIOUS_CONFIGURATION", "OPEN", "mock-" + i,
                    "192.168.90." + i));
        }
        List<Device> devices = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            devices.add(new Device("mock-device-" + i, "10.0." + i / 250 + "." + i % 250, "IOT", "MOCK"));
        }
        ReportData data = new ReportData(base.reportId(), "en", base.homeName(), base.zone(), base.generatedAt(),
                "DISCOVERY", base.scanCompletedAt(), null, null, null, "PORT_SCAN_REQUIRED", 1.0, false, 400, 0,
                many, devices);
        Rendered rendered = RENDERER.render(data);
        String text = text(rendered.pdf());
        assertThat(rendered.pages()).isGreaterThan(5);
        assertThat(text).contains("Score not computed", "page 1 of " + rendered.pages(),
                "page " + rendered.pages() + " of " + rendered.pages(), "100 more devices are not included.");
    }

    /** White label (M17): the brand name heads the report and replaces the creator; MOCK brand. */
    @Test
    void brandNameHeadsTheReport() throws IOException {
        ReportData base = mockHome("it");
        ReportData branded = new ReportData(base.reportId(), base.locale(), base.homeName(), base.zone(),
                base.generatedAt(), base.scanProfile(), base.scanCompletedAt(), base.score(), base.riskLevel(),
                base.rating(), base.notComputedReason(), base.coverage(), base.provisional(), base.hostsDiscovered(),
                base.hostsAnalyzed(), base.findings(), base.devices(), "Installatore MOCK");
        byte[] pdf = RENDERER.render(branded).pdf();
        assertThat(text(pdf)).startsWith("Installatore MOCK");
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertThat(doc.getDocumentInformation().getCreator()).isEqualTo("Installatore MOCK");
        }
        assertThat(text(RENDERER.render(base).pdf())).doesNotContain("Installatore MOCK");
    }

    /** Every finding rule has its title and recommendation in both languages (texts copied from the dashboard). */
    @Test
    void everyFindingRuleHasReportTexts() {
        for (FindingRule rule : FindingRules.all()) {
            String base = "findings.rule." + rule.id().replace('.', '-');
            for (String locale : List.of("it", "en")) {
                assertThat(TEXTS.has(locale, base + ".title")).as(base + " " + locale).isTrue();
                assertThat(TEXTS.has(locale, base + ".recommendation")).as(base + " " + locale).isTrue();
            }
        }
    }

    private static String text(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            PDFTextStripper stripper = new PDFTextStripper();
            stripper.setLineSeparator("\n");
            return stripper.getText(doc);
        }
    }
}
