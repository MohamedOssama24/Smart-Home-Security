package com.shsc.shared.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Dashboard texts the backend needs for PDF reports and alert e-mails (finding rules, severities,
 * types, risk levels, scan profiles, device categories), copied from the Angular i18n files by
 * {@code infrastructure/scripts/sync-report-texts.mjs}. Keys are the dashboard ones
 * ({@code findings.rule.telnet-open.title}); {@code {{name}}} placeholders take the parameters.
 */
@Component
public class UiTexts {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{\\s*(\\w+)\\s*}}");

    private final JsonNode it;
    private final JsonNode en;

    public UiTexts(JsonMapper json) {
        this.it = load(json, "it");
        this.en = load(json, "en");
    }

    private static JsonNode load(JsonMapper json, String lang) {
        try (InputStream in = new ClassPathResource("reports/texts_" + lang + ".json").getInputStream()) {
            return json.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static String lang(String locale) {
        return "en".equals(locale) ? "en" : "it";
    }

    public boolean has(String locale, String key) {
        return node(locale, key).isString();
    }

    /** Text of the key with its parameters; the key itself when missing (never fails). */
    public String text(String locale, String key, Map<String, ?> params) {
        if (key == null) {
            return "";
        }
        JsonNode n = node(locale, key);
        if (!n.isString()) {
            return key;
        }
        Matcher m = PLACEHOLDER.matcher(n.asString());
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            Object value = params == null ? null : params.get(m.group(1));
            m.appendReplacement(out, Matcher.quoteReplacement(value == null ? "?" : String.valueOf(value)));
        }
        m.appendTail(out);
        return out.toString();
    }

    public String text(String locale, String key) {
        return text(locale, key, Map.of());
    }

    private JsonNode node(String locale, String key) {
        JsonNode n = "en".equals(lang(locale)) ? en : it;
        for (String part : key.split("\\.")) {
            n = n.path(part);
        }
        return n;
    }
}
