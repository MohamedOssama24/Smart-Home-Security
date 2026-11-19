package com.shsc.reports;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream.AppendMode;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;

import com.shsc.reports.ReportData.Device;
import com.shsc.reports.ReportData.Finding;
import com.shsc.shared.i18n.UiTexts;

/**
 * PDF security report for non-technical readers (IT/EN, A4): summary with score and coverage,
 * open issues with what they mean and what to do, devices found and the limits of the analysis.
 * <p>
 * Standard PDF fonts only (Helvetica, no embedded files); characters outside their encoding
 * are replaced. The output depends only on {@link ReportData}: same data, same bytes (fixed
 * dates and document ID), which the snapshot tests rely on.
 */
@Component
public class ReportRenderer {

    public static final int MAX_FINDINGS = 100;
    public static final int MAX_DEVICES = 300;

    public record Rendered(byte[] pdf, int pages) {
    }

    private final MessageSource messages;
    private final UiTexts texts;

    public ReportRenderer(MessageSource messages, UiTexts texts) {
        this.messages = messages;
        this.texts = texts;
    }

    public Rendered render(ReportData data) {
        try (PDDocument doc = new PDDocument()) {
            new Writer(doc, data).write();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return new Rendered(out.toByteArray(), doc.getNumberOfPages());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** One rendering: page cursor, fonts and texts of the report language. */
    private final class Writer {

        private static final float MARGIN = 50;
        private static final float TOP = PDRectangle.A4.getHeight() - MARGIN;
        private static final float BOTTOM = 60;
        private static final float WIDTH = PDRectangle.A4.getWidth() - 2 * MARGIN;
        private static final Color TEXT = new Color(0x1f, 0x29, 0x37);
        private static final Color MUTED = new Color(0x55, 0x5f, 0x6d);
        private static final Color RULE = new Color(0xd0, 0xd5, 0xdd);

        private final PDDocument doc;
        private final ReportData data;
        private final String locale;
        private final Locale lang;
        private final PDFont regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
        private final PDFont bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
        private final Map<String, Boolean> encodable = new HashMap<>();
        private final DateTimeFormatter dates;
        private PDPageContentStream cs;
        private float y;

        Writer(PDDocument doc, ReportData data) {
            this.doc = doc;
            this.data = data;
            this.locale = UiTexts.lang(data.locale());
            this.lang = Locale.forLanguageTag(locale);
            this.dates = DateTimeFormatter.ofPattern("en".equals(locale) ? "yyyy-MM-dd HH:mm" : "dd/MM/yyyy HH:mm")
                    .withZone(data.zone());
        }

        void write() throws IOException {
            metadata();
            newPage();
            header();
            summary();
            findings();
            devices();
            limits();
            cs.close();
            footers();
        }

        // --- sections -------------------------------------------------------------------------

        private void header() throws IOException {
            if (data.brandName() != null) {
                text(data.brandName(), bold, 12, MUTED);
                y -= 2;
            }
            text(msg("report.title"), bold, 22, TEXT);
            y -= 6;
            text(msg("report.home", data.homeName()), bold, 13, TEXT);
            text(msg("report.generatedAt", date(data.generatedAt())), regular, 9.5f, MUTED);
            if (data.scanCompletedAt() != null) {
                text(msg("report.scan", ui("scans.profiles." + data.scanProfile()), date(data.scanCompletedAt())),
                        regular, 9.5f, MUTED);
            }
            y -= 8;
            rule();
        }

        private void summary() throws IOException {
            heading(msg("report.section.summary"));
            if (data.score() != null) {
                Color color = levelColor(data.riskLevel());
                float box = 64;
                ensure(box + 10);
                cs.setNonStrokingColor(color);
                cs.addRect(MARGIN, y - box, box, box);
                cs.fill();
                String score = String.valueOf(data.score());
                float size = 26;
                textAt(score, bold, size, Color.WHITE, MARGIN + (box - width(score, bold, size)) / 2, y - 40);
                float x = MARGIN + box + 14;
                float saved = y;
                y -= 4;
                wrapped(msg("report.score", data.score(), ui("risk.level." + data.riskLevel()),
                        ui("risk.rating." + data.rating())), bold, 11.5f, color, x, WIDTH - box - 14);
                wrapped(msg("report.scoreExplained"), regular, 9, MUTED, x, WIDTH - box - 14);
                y = Math.min(y, saved - box) - 10;
            } else if (data.notComputedReason() != null) {
                paragraph(msg("report.notComputed"), regular, 10, TEXT);
            } else {
                paragraph(msg("report.noSnapshot"), regular, 10, TEXT);
            }
            if (data.coverage() != null) {
                paragraph(msg("report.coverage", Math.round(data.coverage() * 100), data.hostsAnalyzed(),
                        data.hostsDiscovered()), regular, 10, TEXT);
                if (data.provisional()) {
                    paragraph(msg("report.provisional"), bold, 10, levelColor("HIGH"));
                }
            }
            int[] counts = new int[5];
            int accepted = 0;
            for (Finding f : data.findings()) {
                if ("ACCEPTED_RISK".equals(f.status())) {
                    accepted++;
                } else {
                    counts[severityIndex(f.severity())]++;
                }
            }
            paragraph(msg("report.counts", counts[0], counts[1], counts[2], counts[3], counts[4]), regular, 10, TEXT);
            if (accepted > 0) {
                paragraph(msg("report.accepted", accepted), regular, 10, TEXT);
            }
            paragraph(msg("report.statusNote"), regular, 8.5f, MUTED);
        }

        private void findings() throws IOException {
            heading(msg("report.section.findings"));
            List<Finding> open = data.findings().stream().filter(f -> !"ACCEPTED_RISK".equals(f.status()))
                    .sorted(Comparator.comparingInt(f -> severityIndex(f.severity()))).toList();
            if (open.isEmpty()) {
                paragraph(msg("report.findings.none"), regular, 10, TEXT);
                return;
            }
            for (Finding f : open.stream().limit(MAX_FINDINGS).toList()) {
                String title = ui(f.titleKey(), f.params());
                ensure(60);
                float top = y;
                int page = doc.getNumberOfPages();
                wrapped(title, bold, 11, TEXT, MARGIN + 10, WIDTH - 10);
                wrapped(msg("report.finding.meta", ui("findings.severity." + f.severity()),
                        ui("findings.type." + f.type() + ".label"), ui("findings.status." + f.status())), regular,
                        8.5f, MUTED, MARGIN + 10, WIDTH - 10);
                wrapped(msg("report.finding.device", f.deviceName(), f.deviceIp()), regular, 9, MUTED, MARGIN + 10,
                        WIDTH - 10);
                String description = describe(f.titleKey(), "description", f.params());
                if (description != null) {
                    wrapped(msg("report.finding.what", description), regular, 9.5f, TEXT, MARGIN + 10, WIDTH - 10);
                }
                if (texts.has(locale, f.recommendationKey())) {
                    wrapped(msg("report.finding.todo", ui(f.recommendationKey(), f.params())), regular, 9.5f, TEXT,
                            MARGIN + 10, WIDTH - 10);
                }
                // severity bar on the left of the issue (when it did not continue on a new page)
                float bottom = y + 2;
                if (page == doc.getNumberOfPages() && top > bottom) {
                    cs.setNonStrokingColor(severityColor(f.severity()));
                    cs.addRect(MARGIN, bottom, 4, top - bottom);
                    cs.fill();
                }
                y -= 10;
            }
            if (open.size() > MAX_FINDINGS) {
                paragraph(msg("report.findings.more", open.size() - MAX_FINDINGS), regular, 9, MUTED);
            }
        }

        private void devices() throws IOException {
            heading(msg("report.section.devices", data.devices().size()));
            float[] columns = { 165, 95, 115, WIDTH - 375 };
            String[] head = { msg("report.devices.name"), msg("report.devices.ip"), msg("report.devices.category"),
                msg("report.devices.manufacturer") };
            row(head, columns, bold, true);
            for (Device d : data.devices().stream().limit(MAX_DEVICES).toList()) {
                row(new String[] { d.name(), d.ip(), ui("devices.categories." + d.category()),
                    d.manufacturer() == null ? "-" : d.manufacturer() }, columns, regular, false);
            }
            if (data.devices().size() > MAX_DEVICES) {
                paragraph(msg("report.devices.more", data.devices().size() - MAX_DEVICES), regular, 9, MUTED);
            }
            y -= 6;
        }

        private void limits() throws IOException {
            heading(msg("report.section.limits"));
            for (int i = 1; i <= 6; i++) {
                ensure(30);
                textAt("-", regular, 9.5f, TEXT, MARGIN, y - 9.5f);
                wrapped(msg("report.limits." + i), regular, 9.5f, TEXT, MARGIN + 10, WIDTH - 10);
                y -= 3;
            }
        }

        // --- layout ---------------------------------------------------------------------------

        private void row(String[] cells, float[] widths, PDFont font, boolean header) throws IOException {
            float size = 8.5f;
            List<List<String>> lines = new ArrayList<>();
            int height = 1;
            for (int i = 0; i < cells.length; i++) {
                List<String> l = wrap(clean(cells[i] == null ? "" : cells[i], font), font, size, widths[i] - 6);
                lines.add(l);
                height = Math.max(height, l.size());
            }
            float rowHeight = height * (size + 2.5f) + 5;
            if (y - rowHeight < BOTTOM) {
                newPage();
            }
            float x = MARGIN;
            for (int i = 0; i < cells.length; i++) {
                float ly = y - size - 2;
                for (String line : lines.get(i)) {
                    textAt(line, font, size, header ? MUTED : TEXT, x, ly);
                    ly -= size + 2.5f;
                }
                x += widths[i];
            }
            y -= rowHeight;
            cs.setStrokingColor(RULE);
            cs.setLineWidth(0.4f);
            cs.moveTo(MARGIN, y + 2);
            cs.lineTo(MARGIN + WIDTH, y + 2);
            cs.stroke();
        }

        private void heading(String title) throws IOException {
            ensure(60);
            y -= 10;
            text(title, bold, 14, TEXT);
            y -= 4;
        }

        private void rule() throws IOException {
            cs.setStrokingColor(RULE);
            cs.setLineWidth(0.8f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(MARGIN + WIDTH, y);
            cs.stroke();
            y -= 6;
        }

        private void paragraph(String s, PDFont font, float size, Color color) throws IOException {
            wrapped(s, font, size, color, MARGIN, WIDTH);
            y -= 4;
        }

        private void text(String s, PDFont font, float size, Color color) throws IOException {
            wrapped(s, font, size, color, MARGIN, WIDTH);
        }

        /** Wrapped text from the cursor down, continuing on a new page when needed. */
        private void wrapped(String s, PDFont font, float size, Color color, float x, float width) throws IOException {
            float leading = size * 1.3f;
            for (String line : wrap(clean(s, font), font, size, width)) {
                if (y - leading < BOTTOM) {
                    newPage();
                }
                y -= leading;
                textAt(line, font, size, color, x, y + (leading - size) / 2);
            }
        }

        private void textAt(String s, PDFont font, float size, Color color, float x, float baseline)
                throws IOException {
            cs.beginText();
            cs.setFont(font, size);
            cs.setNonStrokingColor(color);
            cs.newLineAtOffset(x, baseline);
            cs.showText(clean(s, font));
            cs.endText();
        }

        private void ensure(float space) throws IOException {
            if (y - space < BOTTOM) {
                newPage();
            }
        }

        private void newPage() throws IOException {
            if (cs != null) {
                cs.close();
            }
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            cs = new PDPageContentStream(doc, page);
            y = TOP;
        }

        private void footers() throws IOException {
            int total = doc.getNumberOfPages();
            for (int i = 0; i < total; i++) {
                PDPage page = doc.getPage(i);
                try (PDPageContentStream footer = new PDPageContentStream(doc, page, AppendMode.APPEND, true, true)) {
                    String s = clean(msg("report.footer", data.homeName(), i + 1, total), regular);
                    footer.beginText();
                    footer.setFont(regular, 8);
                    footer.setNonStrokingColor(MUTED);
                    footer.newLineAtOffset(MARGIN, 30);
                    footer.showText(s);
                    footer.endText();
                }
            }
        }

        private void metadata() {
            PDDocumentInformation info = doc.getDocumentInformation();
            info.setTitle(clean(msg("report.title") + " - " + data.homeName(), regular));
            info.setCreator(data.brandName() != null ? clean(data.brandName(), regular) : "Smart Home Security Check");
            info.setProducer("Smart Home Security Check");
            Calendar created = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.ROOT);
            created.setTimeInMillis(data.generatedAt().toEpochMilli());
            info.setCreationDate(created);
            // fixed document ID (derived from the report): same data, same bytes
            byte[] id = digest(String.valueOf(data.reportId()) + data.generatedAt());
            COSArray ids = new COSArray();
            ids.add(new COSString(id));
            ids.add(new COSString(id));
            doc.getDocument().getTrailer().setItem(COSName.ID, ids);
        }

        // --- text helpers ---------------------------------------------------------------------

        private List<String> wrap(String s, PDFont font, float size, float width) throws IOException {
            List<String> out = new ArrayList<>();
            for (String paragraph : s.split("\n", -1)) {
                StringBuilder line = new StringBuilder();
                for (String word : paragraph.split(" ")) {
                    String candidate = line.isEmpty() ? word : line + " " + word;
                    if (width(candidate, font, size) <= width) {
                        line.setLength(0);
                        line.append(candidate);
                        continue;
                    }
                    if (!line.isEmpty()) {
                        out.add(line.toString());
                        line.setLength(0);
                    }
                    // a single word longer than the line (host names, URLs) is cut
                    String rest = word;
                    while (width(rest, font, size) > width && rest.length() > 1) {
                        int n = rest.length() - 1;
                        while (n > 1 && width(rest.substring(0, n), font, size) > width) {
                            n--;
                        }
                        out.add(rest.substring(0, n));
                        rest = rest.substring(n);
                    }
                    line.append(rest);
                }
                out.add(line.toString());
            }
            return out;
        }

        private float width(String s, PDFont font, float size) throws IOException {
            return font.getStringWidth(s) / 1000 * size;
        }

        /** Keeps only characters the standard font can encode (WinAnsi); tabs and controls become spaces. */
        private String clean(String s, PDFont font) {
            StringBuilder out = new StringBuilder(s.length());
            s.codePoints().forEach(cp -> {
                if (cp == '\n') {
                    out.append('\n');
                } else if (Character.isISOControl(cp) || Character.isWhitespace(cp)) {
                    out.append(' ');
                } else {
                    String c = new String(Character.toChars(cp));
                    out.append(encodable.computeIfAbsent(font.getName() + c, k -> canEncode(font, c)) ? c : "?");
                }
            });
            return out.toString();
        }

        private static boolean canEncode(PDFont font, String c) {
            try {
                font.encode(c);
                return true;
            } catch (IOException | IllegalArgumentException e) {
                return false;
            }
        }

        private String msg(String key, Object... args) {
            return messages.getMessage(key, args, lang);
        }

        private String ui(String key) {
            return texts.text(locale, key);
        }

        private String ui(String key, Map<String, Object> params) {
            return texts.text(locale, key, params);
        }

        /** findings.rule.x.title -> findings.rule.x.{part}, or null when there is no such text. */
        private String describe(String titleKey, String part, Map<String, Object> params) {
            if (titleKey == null || !titleKey.endsWith(".title")) {
                return null;
            }
            String key = titleKey.substring(0, titleKey.length() - "title".length()) + part;
            return texts.has(locale, key) ? ui(key, params) : null;
        }

        private String date(Instant instant) {
            return dates.format(instant) + " (" + data.zone().getId() + ")";
        }
    }

    // --- colors -------------------------------------------------------------------------------

    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");

    static int severityIndex(String severity) {
        int i = SEVERITIES.indexOf(severity);
        return i < 0 ? 4 : i;
    }

    private static Color severityColor(String severity) {
        return switch (severity) {
            case "CRITICAL" -> new Color(0x9b, 0x1c, 0x1c);
            case "HIGH" -> new Color(0xc2, 0x41, 0x0c);
            case "MEDIUM" -> new Color(0xb4, 0x83, 0x09);
            case "LOW" -> new Color(0x2f, 0x6f, 0x9f);
            default -> new Color(0x6b, 0x72, 0x80);
        };
    }

    private static Color levelColor(String level) {
        return switch (level == null ? "" : level) {
            case "CRITICAL" -> new Color(0x9b, 0x1c, 0x1c);
            case "HIGH" -> new Color(0xc2, 0x41, 0x0c);
            case "MEDIUM" -> new Color(0xa1, 0x6c, 0x07);
            default -> new Color(0x1f, 0x7a, 0x4d);
        };
    }

    private static byte[] digest(String s) {
        try {
            byte[] full = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(full, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
