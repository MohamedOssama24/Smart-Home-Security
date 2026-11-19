package com.shsc.assistant;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.shsc.assistant.AssistantFacts.Fact;
import com.shsc.assistant.AssistantProvider.Draft;

/**
 * No-hallucination check of an answer against the facts it was built from. Rejects: citations
 * of unknown facts, answers without citations (when there are facts), IP addresses, CVE ids,
 * links or "N/100" scores that do not appear in the facts, empty or oversized texts. A rejected
 * answer is never shown: the service falls back to the deterministic LOCAL provider.
 */
public final class GroundingValidator {

    static final int MAX_ANSWER = 4000;

    private static final Pattern CITATION = Pattern.compile("\\[([SFD]\\d{1,4})]");
    private static final Pattern IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");
    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK = Pattern.compile("(?:https?://|www\\.)\\S+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCORE = Pattern.compile("(?<!\\d)(\\d{1,3})\\s*/\\s*100(?!\\d)");

    private GroundingValidator() {
    }

    /** {@code citations}: the cited fact ids in order of appearance, when grounded. */
    public record Result(boolean grounded, String reason, List<String> citations) {
        static Result rejected(String reason) {
            return new Result(false, reason, List.of());
        }
    }

    public static Result check(Draft draft, AssistantFacts facts) {
        String text = draft == null || draft.text() == null ? "" : draft.text().strip();
        if (text.isEmpty()) {
            return Result.rejected("EMPTY");
        }
        if (text.length() > MAX_ANSWER) {
            return Result.rejected("TOO_LONG");
        }
        if (text.chars().anyMatch(c -> Character.isISOControl(c) && c != '\n')) {
            return Result.rejected("CONTROL_CHARACTERS");
        }
        Map<String, Fact> known = facts.byId();
        Set<String> cited = new LinkedHashSet<>();
        Matcher m = CITATION.matcher(text);
        while (m.find()) {
            cited.add(m.group(1));
        }
        if (draft.citations() != null) {
            for (String id : draft.citations()) {
                if (id == null || !known.containsKey(id)) {
                    return Result.rejected("UNKNOWN_CITATION");
                }
            }
        }
        for (String id : cited) {
            if (!known.containsKey(id)) {
                return Result.rejected("UNKNOWN_CITATION");
            }
        }
        if (!known.isEmpty() && cited.isEmpty()) {
            return Result.rejected("NO_CITATION");
        }
        String corpus = facts.corpus();
        String upperCorpus = corpus.toUpperCase(Locale.ROOT);
        Set<String> ips = new java.util.HashSet<>();
        facts.findings().forEach(f -> ips.add(f.ip()));
        facts.devices().forEach(d -> ips.add(d.ip()));
        Matcher known4 = IPV4.matcher(corpus);
        while (known4.find()) {
            ips.add(known4.group());
        }
        Matcher ip = IPV4.matcher(text);
        while (ip.find()) {
            if (!ips.contains(ip.group())) {
                return Result.rejected("UNKNOWN_IP");
            }
        }
        if (!allIn(CVE, text, upperCorpus, true)) {
            return Result.rejected("UNKNOWN_CVE");
        }
        if (!allIn(LINK, text, corpus, false)) {
            return Result.rejected("UNKNOWN_LINK");
        }
        Matcher s = SCORE.matcher(text);
        while (s.find()) {
            Integer score = facts.score() == null ? null : facts.score().score();
            if (score == null || score != Integer.parseInt(s.group(1))) {
                return Result.rejected("WRONG_SCORE");
            }
        }
        return new Result(true, null, new ArrayList<>(cited));
    }

    private static boolean allIn(Pattern pattern, String text, String corpus, boolean upper) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String value = m.group().replaceAll("[.,;:)\\]]+$", "");
            if (!corpus.contains(upper ? value.toUpperCase(Locale.ROOT) : value)) {
                return false;
            }
        }
        return true;
    }
}
