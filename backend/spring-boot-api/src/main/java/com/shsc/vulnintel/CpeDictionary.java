package com.shsc.vulnintel;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/**
 * Curated map from a declared product (service name + product, e.g. ssh "OpenSSH") to its NVD
 * CPE {@code vendor:product} pairs (docs/19-SECURITY-ANALYSIS.md §3). The whole product name
 * must match: there is no fuzzy matching and no match on the vendor alone. Validated at start.
 */
@Component
public class CpeDictionary {

    static final String RESOURCE = "vulnintel/cpe-dictionary.json";
    private static final Pattern CPE_NAME = Pattern.compile("[a-z0-9_.\\-]{1,64}:[a-z0-9_.\\-]{1,64}");

    record EntryFile(String id, List<String> services, String product, List<String> cpes, String versionConfidence) {
    }

    record DictionaryFile(String version, String description, List<EntryFile> entries) {
    }

    /** A CPE product: vendor and product as written in the NVD. */
    public record CpeProduct(String vendor, String product) {
        public String matchString() {
            return "cpe:2.3:*:" + vendor + ":" + product;
        }
    }

    /** Dictionary entry that matched a declared product. */
    public record Entry(String id, List<CpeProduct> cpes, String versionConfidence) {
    }

    private record Compiled(String id, Set<String> services, Pattern product, List<CpeProduct> cpes,
            String versionConfidence) {
    }

    private final String version;
    private final List<Compiled> entries;

    @Autowired
    public CpeDictionary(JsonMapper json) {
        this(load(json));
    }

    CpeDictionary(DictionaryFile file) {
        if (file.version() == null || !file.version().matches("[0-9A-Za-z.\\-]{1,32}") || file.entries() == null) {
            throw new IllegalStateException("CPE dictionary version missing or invalid");
        }
        Set<String> ids = new HashSet<>();
        List<Compiled> out = new ArrayList<>();
        for (EntryFile e : file.entries()) {
            if (e.id() == null || !ids.add(e.id()) || e.services() == null || e.services().isEmpty()
                    || e.product() == null || e.product().isBlank() || e.cpes() == null || e.cpes().isEmpty()
                    || !List.of("HIGH", "MEDIUM").contains(e.versionConfidence())) {
                throw new IllegalStateException("invalid or duplicated CPE dictionary entry: " + e.id());
            }
            List<CpeProduct> cpes = new ArrayList<>();
            for (String cpe : e.cpes()) {
                if (!CPE_NAME.matcher(cpe).matches()) {
                    throw new IllegalStateException("invalid CPE vendor:product " + cpe);
                }
                String[] parts = cpe.split(":");
                cpes.add(new CpeProduct(parts[0], parts[1]));
            }
            out.add(new Compiled(e.id(), Set.copyOf(e.services()),
                    Pattern.compile(e.product(), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE), List.copyOf(cpes),
                    e.versionConfidence()));
        }
        this.version = file.version();
        this.entries = List.copyOf(out);
    }

    private static DictionaryFile load(JsonMapper json) {
        try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
            return json.readValue(in, DictionaryFile.class);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + RESOURCE, e);
        }
    }

    public String version() {
        return version;
    }

    /** Entry of a product declared by a service, if the whole product name is in the dictionary. */
    public Optional<Entry> lookup(String service, String product) {
        if (service == null || product == null || product.isBlank()) {
            return Optional.empty();
        }
        String name = product.trim().toLowerCase(Locale.ROOT);
        return entries.stream()
                .filter(e -> e.services().contains(service) && e.product().matcher(name).matches())
                .findFirst().map(e -> new Entry(e.id(), e.cpes(), e.versionConfidence()));
    }

    /** Every CPE product of the dictionary: what the NVD synchronization downloads. */
    public List<CpeProduct> products() {
        return entries.stream().flatMap(e -> e.cpes().stream()).distinct().toList();
    }
}
