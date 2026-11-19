package com.shsc.devices.fingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/**
 * Rule + score classification engine (docs/17-DEVICE-FINGERPRINTING.md §3). The ruleset is a
 * versioned JSON file in the repository ({@code fingerprint/rules.json}), validated at
 * startup: an invalid ruleset stops the application instead of classifying badly.
 * <p>
 * Decision: the category with the highest score is chosen only if the score reaches the
 * threshold <b>and</b> it has one STRONG evidence or two MODERATE evidences from independent
 * sources. A single weak hint is never enough. Two categories that both qualify with the same
 * score give UNKNOWN_DEVICE; a qualifying runner-up lowers the confidence by one level.
 */
@Component
public class ClassificationRules {

    static final String RESOURCE = "fingerprint/rules.json";

    record Condition(String field, String matches) {
    }

    record RuleFile(String id, DeviceCategory category, Strength strength, List<Condition> all, String note) {
    }

    record RulesetFile(String version, String description, int threshold, Map<Strength, Integer> weights,
            List<RuleFile> rules) {
    }

    private record Rule(String id, DeviceCategory category, Strength strength, List<CompiledCondition> all) {
    }

    private record CompiledCondition(String field, Pattern pattern) {
    }

    /** A rule satisfied by the host: the sources and values that satisfied it. */
    public record RuleMatch(String ruleId, DeviceCategory category, Strength strength, Set<String> sources,
            List<String> values) {
    }

    /**
     * Result: category (UNKNOWN_DEVICE when not enough evidence), its confidence (null for
     * UNKNOWN_DEVICE), the score, every matched rule (also those of other categories) and the
     * other categories that qualified too (conflicts).
     */
    public record Classification(DeviceCategory category, Confidence confidence, int score, List<RuleMatch> matches,
            List<DeviceCategory> conflicts, String rulesetVersion) {
    }

    private final String version;
    private final int threshold;
    private final Map<Strength, Integer> weights;
    private final List<Rule> rules;

    @Autowired
    public ClassificationRules(JsonMapper json) {
        this(load(json));
    }

    ClassificationRules(RulesetFile file) {
        if (file.version() == null || !file.version().matches("[0-9A-Za-z.\\-]{1,32}")) {
            throw new IllegalStateException("ruleset version missing or invalid");
        }
        if (file.threshold() <= 0 || file.weights() == null || file.weights().size() != Strength.values().length) {
            throw new IllegalStateException("ruleset threshold or weights invalid");
        }
        if (file.weights().get(Strength.WEAK) >= file.threshold()) {
            throw new IllegalStateException("a single weak hint must never reach the threshold");
        }
        Set<String> ids = new HashSet<>();
        List<Rule> compiled = new ArrayList<>();
        for (RuleFile r : file.rules()) {
            if (r.id() == null || !ids.add(r.id()) || r.category() == null || r.strength() == null
                    || r.category() == DeviceCategory.UNKNOWN_DEVICE || r.all() == null || r.all().isEmpty()) {
                throw new IllegalStateException("invalid or duplicated rule: " + r.id());
            }
            compiled.add(new Rule(r.id(), r.category(), r.strength(), r.all().stream()
                    .map(c -> new CompiledCondition(c.field(),
                            Pattern.compile(c.matches(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE)))
                    .toList()));
        }
        this.version = file.version();
        this.threshold = file.threshold();
        this.weights = new EnumMap<>(file.weights());
        this.rules = List.copyOf(compiled);
    }

    private static RulesetFile load(JsonMapper json) {
        try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
            return json.readValue(in, RulesetFile.class);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + RESOURCE, e);
        }
    }

    public String version() {
        return version;
    }

    public Classification classify(List<Signal> signals) {
        List<RuleMatch> matches = new ArrayList<>();
        for (Rule rule : rules) {
            match(rule, signals).ifPresent(matches::add);
        }
        record Candidate(DeviceCategory category, int score, Confidence confidence) {
        }
        List<Candidate> qualified = new ArrayList<>();
        for (DeviceCategory category : DeviceCategory.values()) {
            List<RuleMatch> mine = matches.stream().filter(m -> m.category() == category).toList();
            if (mine.isEmpty()) {
                continue;
            }
            int score = mine.stream().mapToInt(m -> weights.get(m.strength())).sum();
            qualification(mine).filter(c -> score >= threshold)
                    .ifPresent(c -> qualified.add(new Candidate(category, score, c)));
        }
        qualified.sort(Comparator.comparingInt(Candidate::score).reversed());
        if (qualified.isEmpty()) {
            return new Classification(DeviceCategory.UNKNOWN_DEVICE, null, 0, matches, List.of(), version);
        }
        List<DeviceCategory> conflicts = qualified.stream().skip(1).map(Candidate::category).toList();
        Candidate best = qualified.get(0);
        if (qualified.size() > 1 && qualified.get(1).score() == best.score()) {
            // two categories equally supported: not decided
            return new Classification(DeviceCategory.UNKNOWN_DEVICE, null, best.score(), matches,
                    qualified.stream().map(Candidate::category).toList(), version);
        }
        Confidence confidence = conflicts.isEmpty() ? best.confidence() : best.confidence().lower();
        return new Classification(best.category(), confidence, best.score(), matches, conflicts, version);
    }

    /**
     * Whether the matches of one category are enough, and with which confidence: one STRONG
     * evidence confirmed by an independent source → HIGH; one STRONG alone or two MODERATE
     * from independent sources → MEDIUM; otherwise not enough.
     */
    private static Optional<Confidence> qualification(List<RuleMatch> mine) {
        List<RuleMatch> strong = mine.stream().filter(m -> m.strength() == Strength.STRONG).toList();
        if (!strong.isEmpty()) {
            Set<String> strongSources = strong.get(0).sources();
            boolean confirmed = mine.stream().filter(m -> m != strong.get(0))
                    .filter(m -> m.strength() != Strength.WEAK)
                    .anyMatch(m -> !strongSources.containsAll(m.sources()));
            return Optional.of(confirmed ? Confidence.HIGH : Confidence.MEDIUM);
        }
        List<RuleMatch> moderate = mine.stream().filter(m -> m.strength() == Strength.MODERATE).toList();
        for (int i = 0; i < moderate.size(); i++) {
            for (int j = i + 1; j < moderate.size(); j++) {
                if (!moderate.get(i).sources().equals(moderate.get(j).sources())) {
                    return Optional.of(Confidence.MEDIUM);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<RuleMatch> match(Rule rule, List<Signal> signals) {
        Set<String> sources = new LinkedHashSet<>();
        List<String> values = new ArrayList<>();
        for (CompiledCondition c : rule.all()) {
            Optional<Signal> hit = signals.stream()
                    .filter(s -> s.field().equals(c.field()) && c.pattern().matcher(s.value()).find()).findFirst();
            if (hit.isEmpty()) {
                return Optional.empty();
            }
            sources.add(hit.get().source());
            values.add(hit.get().value());
        }
        return Optional.of(new RuleMatch(rule.id(), rule.category(), rule.strength(),
                Collections.unmodifiableSet(new TreeSet<>(sources)),
                List.copyOf(values)));
    }
}
