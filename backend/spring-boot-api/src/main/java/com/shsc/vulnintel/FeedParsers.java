package com.shsc.vulnintel;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import com.shsc.vulnintel.CpeDictionary.CpeProduct;
import com.shsc.vulnintel.VulnerabilityRepository.CpeMatch;
import com.shsc.vulnintel.VulnerabilityRepository.Cve;
import com.shsc.vulnintel.VulnerabilityRepository.EpssScore;
import com.shsc.vulnintel.VulnerabilityRepository.KevEntry;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

/**
 * Parsers of the public feeds (docs/19-SECURITY-ANALYSIS.md §2). Every value is validated and
 * truncated to the column limits; a malformed document is refused as a whole
 * ({@link InvalidFeedException}), a malformed record is skipped.
 */
final class FeedParsers {

    static final Pattern CVE_ID = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}");
    private static final int MAX_DESCRIPTION = 4000;
    private static final int MAX_REFERENCES = 20;
    private static final int MAX_CWE = 16;
    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");

    /** The document is not what the feed should return. */
    static final class InvalidFeedException extends RuntimeException {
        InvalidFeedException(String message) {
            super(message);
        }
    }

    /** One page of the NVD CVE API: CVEs kept, rejected CVE ids, total of the query. */
    record NvdPage(List<Cve> cves, List<String> rejected, int startIndex, int resultsPerPage, int totalResults) {
    }

    private FeedParsers() {
    }

    /**
     * Parses one NVD CVE API 2.0 page. Only the criteria of {@code products} are kept (the CVE was
     * returned because of one of them); a configuration with a negated node is skipped, an AND
     * configuration (vulnerable only together with another component) marks its criteria as
     * {@code requiresPlatform}.
     */
    static NvdPage nvd(JsonMapper json, byte[] body, Set<CpeProduct> products) {
        JsonNode root = read(json, body);
        JsonNode items = root.path("vulnerabilities");
        if (!items.isArray() || !root.path("totalResults").isNumber()) {
            throw new InvalidFeedException("not an NVD CVE API 2.0 document");
        }
        List<Cve> cves = new ArrayList<>();
        List<String> rejected = new ArrayList<>();
        for (JsonNode item : items) {
            JsonNode cve = item.path("cve");
            String id = text(cve.path("id"));
            if (id == null || !CVE_ID.matcher(id).matches()) {
                continue;
            }
            String status = truncate(text(cve.path("vulnStatus")), 40);
            if ("Rejected".equalsIgnoreCase(status)) {
                rejected.add(id);
                continue;
            }
            List<CpeMatch> matches = criteria(cve.path("configurations"), products);
            if (matches.isEmpty()) {
                continue;
            }
            Metric metric = metric(cve.path("metrics"));
            cves.add(new Cve(id, timestamp(text(cve.path("published"))), timestamp(text(cve.path("lastModified"))),
                    truncate(english(cve.path("descriptions")), MAX_DESCRIPTION), metric.version(), metric.score(),
                    truncate(metric.vector(), 200), metric.severity(), cwe(cve.path("weaknesses")),
                    references(json, cve.path("references")), status, matches));
        }
        return new NvdPage(cves, rejected, root.path("startIndex").asInt(), root.path("resultsPerPage").asInt(),
                root.path("totalResults").asInt());
    }

    /** CISA Known Exploited Vulnerabilities catalog (JSON feed). */
    static List<KevEntry> kev(JsonMapper json, byte[] body) {
        JsonNode root = read(json, body);
        JsonNode items = root.path("vulnerabilities");
        if (!items.isArray() || text(root.path("catalogVersion")) == null) {
            throw new InvalidFeedException("not a KEV catalog");
        }
        List<KevEntry> out = new ArrayList<>();
        for (JsonNode k : items) {
            String id = text(k.path("cveID"));
            LocalDate added = date(text(k.path("dateAdded")));
            if (id == null || !CVE_ID.matcher(id).matches() || added == null) {
                continue;
            }
            out.add(new KevEntry(id, truncate(text(k.path("vendorProject")), 255), truncate(text(k.path("product")), 255),
                    truncate(text(k.path("vulnerabilityName")), 512), added, date(text(k.path("dueDate"))),
                    "known".equalsIgnoreCase(text(k.path("knownRansomwareCampaignUse")))));
        }
        if (out.isEmpty()) {
            throw new InvalidFeedException("empty KEV catalog");
        }
        return out;
    }

    /** FIRST EPSS API answer ({@code data: [{cve, epss, percentile, date}]}). */
    static List<EpssScore> epss(JsonMapper json, byte[] body) {
        JsonNode root = read(json, body);
        JsonNode items = root.path("data");
        if (!items.isArray()) {
            throw new InvalidFeedException("not an EPSS answer");
        }
        List<EpssScore> out = new ArrayList<>();
        for (JsonNode e : items) {
            String id = text(e.path("cve"));
            BigDecimal score = probability(text(e.path("epss")));
            BigDecimal percentile = probability(text(e.path("percentile")));
            if (id == null || !CVE_ID.matcher(id).matches() || score == null || percentile == null) {
                continue;
            }
            out.add(new EpssScore(id, score, percentile, date(text(e.path("date")))));
        }
        return out;
    }

    // --- NVD details --------------------------------------------------------------------

    private static List<CpeMatch> criteria(JsonNode configurations, Set<CpeProduct> products) {
        Set<CpeMatch> out = new LinkedHashSet<>();
        for (JsonNode config : configurations) {
            JsonNode nodes = config.path("nodes");
            boolean negated = config.path("negate").asBoolean(false);
            for (JsonNode node : nodes) {
                negated |= node.path("negate").asBoolean(false);
            }
            if (negated) {
                continue; // "vulnerable unless ...": never matched automatically
            }
            boolean configAnd = "AND".equalsIgnoreCase(text(config.path("operator"))) || nodes.size() > 1;
            for (JsonNode node : nodes) {
                JsonNode matches = node.path("cpeMatch");
                boolean nodeAnd = "AND".equalsIgnoreCase(text(node.path("operator"))) && matches.size() > 1;
                for (JsonNode m : matches) {
                    if (!m.path("vulnerable").asBoolean(false)) {
                        continue;
                    }
                    CpeMatch parsed = cpe(text(m.path("criteria")), text(m.path("versionStartIncluding")),
                            text(m.path("versionStartExcluding")), text(m.path("versionEndIncluding")),
                            text(m.path("versionEndExcluding")), configAnd || nodeAnd);
                    if (parsed != null && products.contains(new CpeProduct(parsed.vendor(), parsed.product()))) {
                        out.add(parsed);
                    }
                }
            }
        }
        return List.copyOf(out);
    }

    /** Splits a CPE 2.3 formatted string (":" may be escaped with "\"). */
    static CpeMatch cpe(String cpe23, String startIncl, String startExcl, String endIncl, String endExcl,
            boolean requiresPlatform) {
        if (cpe23 == null || cpe23.length() > 512 || !cpe23.startsWith("cpe:2.3:")) {
            return null;
        }
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < cpe23.length(); i++) {
            char c = cpe23.charAt(i);
            if (c == '\\' && i + 1 < cpe23.length()) {
                current.append(c).append(cpe23.charAt(++i));
            } else if (c == ':') {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        if (fields.size() != 13 || !List.of("a", "o", "h").contains(fields.get(2))) {
            return null;
        }
        String vendor = fields.get(3).toLowerCase(Locale.ROOT);
        String product = fields.get(4).toLowerCase(Locale.ROOT);
        if (vendor.isEmpty() || vendor.length() > 128 || product.isEmpty() || product.length() > 128) {
            return null;
        }
        return new CpeMatch(cpe23, fields.get(2), vendor, product, version(fields.get(5)), version(fields.get(6)),
                version(startIncl), version(startExcl), version(endIncl), version(endExcl), requiresPlatform);
    }

    private static String version(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String v = value.replace("\\", "");
        return v.length() > 64 ? null : v;
    }

    private record Metric(String version, BigDecimal score, String vector, String severity) {
    }

    /** CVSS v4.0, then v3.1, v3.0, v2: the primary (NVD) metric first, otherwise the first one. */
    private static Metric metric(JsonNode metrics) {
        for (String key : List.of("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")) {
            JsonNode list = metrics.path(key);
            if (!list.isArray() || list.isEmpty()) {
                continue;
            }
            JsonNode chosen = list.get(0);
            for (JsonNode m : list) {
                if ("Primary".equalsIgnoreCase(text(m.path("type")))) {
                    chosen = m;
                    break;
                }
            }
            JsonNode data = chosen.path("cvssData");
            String version = text(data.path("version"));
            BigDecimal score = data.path("baseScore").isNumber()
                    ? data.path("baseScore").decimalValue().setScale(1, RoundingMode.HALF_UP) : null;
            if (score == null || score.compareTo(BigDecimal.ZERO) < 0 || score.compareTo(BigDecimal.TEN) > 0
                    || !List.of("4.0", "3.1", "3.0", "2.0").contains(version)) {
                continue;
            }
            String severity = text(data.path("baseSeverity"));
            if (severity == null) {
                severity = text(chosen.path("baseSeverity")); // CVSS v2: outside cvssData
            }
            severity = severity == null ? null : severity.toUpperCase(Locale.ROOT);
            return new Metric(version, score, text(data.path("vectorString")),
                    SEVERITIES.contains(severity) ? severity : null);
        }
        return new Metric(null, null, null, null);
    }

    private static List<String> cwe(JsonNode weaknesses) {
        Set<String> out = new LinkedHashSet<>();
        for (JsonNode w : weaknesses) {
            for (JsonNode d : w.path("description")) {
                String value = text(d.path("value"));
                if (value != null && value.matches("CWE-[0-9]{1,6}") && out.size() < MAX_CWE) {
                    out.add(value);
                }
            }
        }
        return List.copyOf(out);
    }

    private static String references(JsonMapper json, JsonNode references) {
        ArrayNode out = json.createArrayNode();
        for (JsonNode r : references) {
            String url = text(r.path("url"));
            if (url != null && url.length() <= 300 && (url.startsWith("https://") || url.startsWith("http://"))
                    && out.size() < MAX_REFERENCES) {
                out.add(url);
            }
        }
        return json.writeValueAsString(out);
    }

    private static String english(JsonNode descriptions) {
        String first = null;
        for (JsonNode d : descriptions) {
            String value = text(d.path("value"));
            if ("en".equalsIgnoreCase(text(d.path("lang")))) {
                return value;
            }
            first = first == null ? value : first;
        }
        return first;
    }

    // --- helpers ------------------------------------------------------------------------

    private static JsonNode read(JsonMapper json, byte[] body) {
        try {
            JsonNode root = json.readTree(body);
            if (root == null || !root.isObject()) {
                throw new InvalidFeedException("not a JSON object");
            }
            return root;
        } catch (RuntimeException e) {
            if (e instanceof InvalidFeedException invalid) {
                throw invalid;
            }
            throw new InvalidFeedException("malformed JSON");
        }
    }

    static String text(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull() || node.isContainer()) {
            return null;
        }
        String value = node.asString().strip();
        return value.isEmpty() ? null : value.replaceAll("\\p{Cntrl}", " ");
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    /** NVD timestamps have no zone: they are UTC. */
    private static Instant timestamp(String value) {
        if (value == null) {
            return null;
        }
        try {
            return value.endsWith("Z") ? Instant.parse(value) : LocalDateTime.parse(value).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static LocalDate date(String value) {
        if (value == null) {
            return null;
        }
        try {
            return LocalDate.parse(value.length() > 10 ? value.substring(0, 10) : value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static BigDecimal probability(String value) {
        if (value == null) {
            return null;
        }
        try {
            BigDecimal p = new BigDecimal(value).setScale(5, RoundingMode.HALF_UP);
            return p.signum() < 0 || p.compareTo(BigDecimal.ONE) > 0 ? null : p;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
