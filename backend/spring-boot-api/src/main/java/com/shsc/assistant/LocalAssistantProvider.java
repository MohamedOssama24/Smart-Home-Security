package com.shsc.assistant;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.shsc.assistant.AssistantFacts.Device;
import com.shsc.assistant.AssistantFacts.Finding;
import com.shsc.assistant.AssistantFacts.Score;

/**
 * Deterministic provider (default, offline, free): recognises the intent of the question with
 * keywords (IT/EN) and composes the answer only from the facts, citing each of them. It is also
 * the fallback of every other provider, so it must never invent anything.
 */
@Component
public class LocalAssistantProvider implements AssistantProvider {

    enum Intent { ACTION, DEVICE, RISK, FINDINGS, DEVICES, SUMMARY }

    private static final int MAX_LISTED = 5;
    private static final int MAX_DEVICES_LISTED = 10;

    private static final String ACT_IT = "avvia|avviare|esegui|eseguire|lancia|lanciare|elimina|eliminare|cancella"
            + "|cancellare|blocca|bloccare|disattiva|disattivare|spegni|spegnere|riavvia|riavviare|aggiorna|aggiornare"
            + "|modifica|modificare|cambia|cambiare|chiudi|chiudere|apri|aprire|correggi|correggere|risolvi|risolvere"
            + "|scansiona|scansionare|invia|inviare";
    private static final String ACT_EN = "start|run|launch|delete|remove|block|disable|turn off|shut down|reboot"
            + "|restart|update|upgrade|change|modify|close|open|fix|resolve|scan|send";
    private static final Pattern ACTION = Pattern.compile(
            "^(?:per favore\\s+|please\\s+)?(?:" + ACT_IT + "|" + ACT_EN + ")\\b"
                    + "|\\b(?:puoi|potresti|riesci a|can you|could you|would you|please)\\s+(?:" + ACT_IT + "|"
                    + ACT_EN + ")\\b");
    private static final Pattern RISK = Pattern.compile(
            "\\b(?:rischi\\w*|punteggi\\w*|score|risk\\w*|valutazion\\w*|rating|quanto (?:e|sono) sicur\\w*"
                    + "|how (?:safe|secure)|sicurezza generale|overall)\\b");
    private static final Pattern FINDINGS = Pattern.compile(
            "\\b(?:problem\\w*|vulnerabil\\w*|finding\\w*|issue\\w*|critic\\w*|grav\\w*|priorit\\w*|consigl\\w*"
                    + "|raccomand\\w*|recommend\\w*|cosa (?:devo|posso|dovrei) fare|what should i|first|prima"
                    + "|risolv\\w*|correg\\w*|fix\\w*|cve)\\b");
    private static final Pattern DEVICES = Pattern.compile(
            "\\b(?:dispositiv\\w*|device\\w*|apparecch\\w*|quanti|how many|host\\w*|inventario|inventory"
                    + "|telecamer\\w*|camera\\w*|router|stampant\\w*|printer\\w*|tv|nas)\\b");

    @Override
    public String name() {
        return "LOCAL";
    }

    @Override
    public boolean available() {
        return true;
    }

    @Override
    public Draft answer(String question, String locale, AssistantFacts facts) {
        T t = "en".equals(locale) ? T.EN : T.IT;
        String q = normalize(question);
        Intent intent = intent(q, facts);
        if (intent == Intent.ACTION) {
            return new Draft(t.noActions, List.of());
        }
        if (facts.empty()) {
            return new Draft(t.noData, List.of());
        }
        StringBuilder out = new StringBuilder();
        List<String> cited = new ArrayList<>();
        switch (intent) {
            case DEVICE -> device(matchDevice(q, facts), facts, t, out, cited);
            case RISK -> {
                risk(facts, t, out, cited);
                severityCounts(facts, t, out);
            }
            case FINDINGS -> findings(facts, t, out, cited, MAX_LISTED);
            case DEVICES -> devices(facts, t, out, cited);
            default -> {
                risk(facts, t, out, cited);
                findings(facts, t, out, cited, 3);
                out.append("\n\n").append(t.hint);
            }
        }
        if (cited.isEmpty() && !facts.devices().isEmpty()) {
            // nothing more specific: at least anchor the answer to the inventory
            Device first = facts.devices().getFirst();
            out.append("\n").append(t.devicesCount.formatted(facts.devices().size())).append(" [")
                    .append(first.id()).append("]");
            cited.add(first.id());
        }
        if (facts.truncated()) {
            out.append("\n\n").append(t.truncated);
        }
        return new Draft(out.toString().strip(), List.copyOf(cited));
    }

    Intent intent(String q, AssistantFacts facts) {
        if (ACTION.matcher(q).find()) {
            return Intent.ACTION;
        }
        if (matchDevice(q, facts) != null) {
            return Intent.DEVICE;
        }
        if (FINDINGS.matcher(q).find()) {
            return Intent.FINDINGS;
        }
        if (RISK.matcher(q).find()) {
            return Intent.RISK;
        }
        if (DEVICES.matcher(q).find()) {
            return Intent.DEVICES;
        }
        return Intent.SUMMARY;
    }

    /** A device named in the question by IP address or by name (at least 3 characters). */
    private static Device matchDevice(String q, AssistantFacts facts) {
        for (Device d : facts.devices()) {
            if (d.ip() != null && Pattern.compile("(?<![\\d.])" + Pattern.quote(d.ip()) + "(?![\\d.])")
                    .matcher(q).find()) {
                return d;
            }
        }
        for (Device d : facts.devices()) {
            String name = d.name() == null ? "" : normalize(d.name());
            if (name.length() >= 3 && !name.equals(d.ip()) && q.contains(name)) {
                return d;
            }
        }
        return null;
    }

    private static void risk(AssistantFacts facts, T t, StringBuilder out, List<String> cited) {
        Score s = facts.score();
        if (s == null) {
            out.append(t.noScore);
            return;
        }
        if (s.score() == null) {
            out.append(t.notComputed.formatted(s.notComputedReason() == null ? "-" : s.notComputedReason()));
        } else {
            out.append(t.score.formatted(s.score(), t.level(s.riskLevel())));
            if (s.coverage() != null) {
                out.append(" ").append(t.coverage.formatted(Math.round(s.coverage() * 100)));
            }
            if (s.provisional()) {
                out.append(" ").append(t.provisional);
            }
        }
        out.append(" [").append(s.id()).append("]");
        cited.add(s.id());
    }

    private static void severityCounts(AssistantFacts facts, T t, StringBuilder out) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        facts.findings().forEach(f -> counts.merge(Severity.of(f.severity()), 1, Integer::sum));
        if (counts.isEmpty()) {
            out.append("\n").append(t.noFindings);
            return;
        }
        List<String> parts = new ArrayList<>();
        counts.forEach((sev, n) -> parts.add(n + " " + t.level(sev.name())));
        out.append("\n").append(t.openFindings.formatted(String.join(", ", parts)));
    }

    private static void findings(AssistantFacts facts, T t, StringBuilder out, List<String> cited, int max) {
        if (!out.isEmpty()) {
            out.append("\n\n");
        }
        if (facts.findings().isEmpty()) {
            out.append(t.noFindings);
            return;
        }
        out.append(t.priorities.formatted(Math.min(max, facts.findings().size()), facts.findings().size()));
        for (Finding f : facts.findings().subList(0, Math.min(max, facts.findings().size()))) {
            finding(f, t, out, cited);
        }
    }

    private static void finding(Finding f, T t, StringBuilder out, List<String> cited) {
        out.append("\n- ").append(f.title()).append(" (").append(t.level(f.severity()));
        if (f.ip() != null) {
            out.append(", ").append(f.deviceName() == null || f.deviceName().equals(f.ip()) ? f.ip()
                    : f.deviceName() + " " + f.ip());
        }
        out.append(") [").append(f.id()).append("]");
        cited.add(f.id());
        if (f.recommendation() != null) {
            out.append("\n  ").append(t.todo).append(" ").append(f.recommendation());
        }
    }

    private static void devices(AssistantFacts facts, T t, StringBuilder out, List<String> cited) {
        out.append(t.devicesCount.formatted(facts.devices().size()));
        for (Device d : facts.devices().subList(0, Math.min(MAX_DEVICES_LISTED, facts.devices().size()))) {
            out.append("\n- ").append(describe(d, t)).append(" [").append(d.id()).append("]");
            cited.add(d.id());
        }
        if (facts.devices().size() > MAX_DEVICES_LISTED) {
            out.append("\n").append(t.more.formatted(facts.devices().size() - MAX_DEVICES_LISTED));
        }
    }

    private static void device(Device d, AssistantFacts facts, T t, StringBuilder out, List<String> cited) {
        out.append(describe(d, t)).append(" [").append(d.id()).append("]");
        cited.add(d.id());
        List<Finding> own = facts.findings().stream().filter(f -> d.id().equals(f.deviceId())).toList();
        if (own.isEmpty()) {
            out.append("\n").append(t.deviceClean);
            return;
        }
        out.append("\n").append(t.deviceFindings.formatted(own.size()));
        own.stream().limit(MAX_LISTED).forEach(f -> finding(f, t, out, cited));
    }

    private static String describe(Device d, T t) {
        StringBuilder s = new StringBuilder(d.name() == null ? d.ip() : d.name());
        if (d.ip() != null && !d.ip().equals(d.name())) {
            s.append(" (").append(d.ip()).append(")");
        }
        List<String> attrs = new ArrayList<>();
        if (d.category() != null) {
            attrs.add(t.category + " " + d.category());
        }
        if (d.manufacturer() != null) {
            attrs.add(t.manufacturer + " " + d.manufacturer());
        }
        if (!attrs.isEmpty()) {
            s.append(": ").append(String.join(", ", attrs));
        }
        return s.toString();
    }

    static String normalize(String s) {
        String n = Normalizer.normalize(s == null ? "" : s, Normalizer.Form.NFD).replaceAll("\\p{M}", "");
        return n.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").strip();
    }

    private enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO;

        static Severity of(String s) {
            try {
                return s == null ? INFO : valueOf(s);
            } catch (IllegalArgumentException e) {
                return INFO;
            }
        }
    }

    /** Fixed texts of the answers. */
    private enum T {
        IT("Posso solo spiegare i dati della tua casa: non eseguo azioni (scansioni, modifiche, blocchi). "
                + "Puoi farle tu dalla dashboard.",
                "Non ci sono ancora dati per questa casa: avvia una scansione dalla dashboard e poi chiedimi di nuovo.",
                "Il punteggio di rischio non è ancora disponibile.",
                "Il punteggio di rischio non è stato calcolato (motivo: %s).",
                "Punteggio di rischio: %d/100, livello %s.", "Copertura dell'analisi: %d%%.",
                "È un punteggio provvisorio.", "Problemi aperti: %s.", "Non ci sono problemi aperti.",
                "Ecco i %d problemi più importanti (su %d aperti):", "Cosa fare:", "Dispositivi rilevati: %d.",
                "…e altri %d.", "Per questo dispositivo non ci sono problemi aperti.",
                "Problemi aperti su questo dispositivo: %d.", "categoria", "produttore",
                "Puoi chiedermi del rischio, dei problemi da risolvere per primi o di un dispositivo (nome o IP).",
                "Nota: la casa ha molti dati, considero solo i primi."),
        EN("I can only explain the data of your home: I do not perform actions (scans, changes, blocks). "
                + "You can do them from the dashboard.",
                "There is no data for this home yet: run a scan from the dashboard, then ask me again.",
                "The risk score is not available yet.",
                "The risk score was not computed (reason: %s).",
                "Risk score: %d/100, level %s.", "Analysis coverage: %d%%.",
                "This score is provisional.", "Open issues: %s.", "There are no open issues.",
                "These are the %d most important issues (of %d open):", "What to do:", "Devices found: %d.",
                "…and %d more.", "This device has no open issues.",
                "Open issues on this device: %d.", "category", "manufacturer",
                "You can ask me about the risk, the issues to fix first or a device (name or IP).",
                "Note: the home has a lot of data, only the first items are considered.");

        final String noActions, noData, noScore, notComputed, score, coverage, provisional, openFindings,
                noFindings, priorities, todo, devicesCount, more, deviceClean, deviceFindings, category,
                manufacturer, hint, truncated;

        T(String noActions, String noData, String noScore, String notComputed, String score, String coverage,
                String provisional, String openFindings, String noFindings, String priorities, String todo,
                String devicesCount, String more, String deviceClean, String deviceFindings, String category,
                String manufacturer, String hint, String truncated) {
            this.noActions = noActions;
            this.noData = noData;
            this.noScore = noScore;
            this.notComputed = notComputed;
            this.score = score;
            this.coverage = coverage;
            this.provisional = provisional;
            this.openFindings = openFindings;
            this.noFindings = noFindings;
            this.priorities = priorities;
            this.todo = todo;
            this.devicesCount = devicesCount;
            this.more = more;
            this.deviceClean = deviceClean;
            this.deviceFindings = deviceFindings;
            this.category = category;
            this.manufacturer = manufacturer;
            this.hint = hint;
            this.truncated = truncated;
        }

        String level(String severity) {
            boolean en = this == EN;
            return switch (severity == null ? "" : severity) {
                case "CRITICAL" -> en ? "critical" : "critico";
                case "HIGH" -> en ? "high" : "alto";
                case "MEDIUM" -> en ? "medium" : "medio";
                case "LOW" -> en ? "low" : "basso";
                case "INFO" -> "info";
                default -> severity == null ? "-" : severity.toLowerCase(Locale.ROOT);
            };
        }
    }
}
