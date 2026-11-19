package com.shsc.alerts;

import java.net.URI;
import java.util.Locale;
import java.util.Map;

import org.springframework.context.MessageSource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Component;

import com.shsc.alerts.AlertRepository.DeliveryJob;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.i18n.UiTexts;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Text of an alert e-mail in the recipient's language. It repeats only what the user can read in
 * the dashboard (no evidence, no secrets) and links to it.
 */
@Component
public class AlertMailer {

    private final MessageSource messages;
    private final UiTexts texts;
    private final JsonMapper json;
    private final URI baseUrl;
    private final String from;

    public AlertMailer(MessageSource messages, UiTexts texts, JsonMapper json, ShscProperties properties) {
        this.messages = messages;
        this.texts = texts;
        this.json = json;
        this.baseUrl = properties.publicBaseUrl();
        this.from = properties.mail().from();
    }

    /** Title shown in the e-mail subject (the dashboard builds its own from the same payload). */
    public String title(String locale, String type, JsonNode p) {
        Locale lang = Locale.forLanguageTag(UiTexts.lang(locale));
        return switch (AlertType.valueOf(type)) {
            case NEW_FINDING -> msg("alert.title.NEW_FINDING", lang, findingTitle(locale, p),
                    texts.text(locale, "findings.severity." + p.path("findingSeverity").asString()));
            case FINDING_RESOLVED -> msg("alert.title.FINDING_RESOLVED", lang, findingTitle(locale, p));
            case SCORE_DROPPED -> msg("alert.title.SCORE_DROPPED", lang, p.path("score").asInt(),
                    p.path("scoreChange").asInt());
            case NEW_DEVICE -> p.path("count").asInt() > 1
                    ? msg("alert.title.NEW_DEVICES", lang, p.path("count").asInt())
                    : msg("alert.title.NEW_DEVICE", lang, p.path("devices").path(0).path("name").asString());
            case SCAN_FAILED -> msg("alert.title.SCAN_FAILED", lang, p.path("reason").asString());
            case AGENT_OFFLINE -> msg("alert.title.AGENT_OFFLINE", lang, p.path("agentName").asString());
        };
    }

    SimpleMailMessage build(DeliveryJob job) {
        JsonNode p = json.readTree(job.payloadJson());
        String locale = UiTexts.lang(job.locale());
        Locale lang = Locale.forLanguageTag(locale);
        String title = title(locale, job.type(), p);
        StringBuilder detail = new StringBuilder();
        if (p.has("deviceName")) {
            detail.append(msg("alert.detail.device", lang, p.path("deviceName").asString(),
                    p.path("deviceIp").asString())).append('\n');
        }
        if ("NEW_FINDING".equals(job.type())) {
            String key = recommendationKey(p);
            if (texts.has(locale, key)) {
                detail.append(msg("alert.detail.recommendation", lang, texts.text(locale, key, params(p))))
                        .append('\n');
            }
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(job.email());
        message.setSubject(msg("alert.mail.subject", lang, title));
        message.setText(msg("alert.mail.body", lang, job.displayName(), title, job.homeName(), detail.toString(),
                baseUrl.resolve("/alerts"), baseUrl.resolve("/alerts/preferences")));
        return message;
    }

    private String findingTitle(String locale, JsonNode p) {
        return texts.text(locale, p.path("titleKey").asString(), params(p));
    }

    /** findings.rule.x.title -> findings.rule.x.recommendation */
    private static String recommendationKey(JsonNode p) {
        String title = p.path("titleKey").asString();
        return title.endsWith(".title") ? title.substring(0, title.length() - ".title".length()) + ".recommendation"
                : title;
    }

    private Map<String, Object> params(JsonNode p) {
        return p.path("params").isObject() ? json.convertValue(p.path("params"), new TypeReference<Map<String, Object>>() {
        }) : Map.of();
    }

    private String msg(String key, Locale lang, Object... args) {
        return messages.getMessage(key, args, lang);
    }
}
