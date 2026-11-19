package com.shsc.devices.oui;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parser of the public IEEE registration authority CSV files (MA-L {@code oui.csv}, MA-M
 * {@code mam.csv}, MA-S {@code oui36.csv}): {@code Registry,Assignment,Organization
 * Name,Organization Address}, RFC 4180 quoting. Rows of other registries (IAB, CID) and
 * malformed rows are skipped and counted.
 */
public final class OuiRegistryParser {

    public record Entry(String prefix, int prefixLength, String organization, String registry) {
    }

    public record Result(List<Entry> entries, int skipped) {
    }

    private static final Map<String, Integer> LENGTHS = Map.of("MA-L", 24, "MA-M", 28, "MA-S", 36);
    private static final int MAX_ORGANIZATION = 255;

    private OuiRegistryParser() {
    }

    public static Result parse(Reader input) throws IOException {
        List<Entry> entries = new ArrayList<>();
        int skipped = 0;
        BufferedReader reader = new BufferedReader(input);
        List<String> record;
        boolean header = true;
        while ((record = next(reader)) != null) {
            if (header) {
                header = false;
                if (!record.isEmpty() && record.get(0).trim().equalsIgnoreCase("Registry")) {
                    continue;
                }
            }
            if (record.size() < 3) {
                skipped++;
                continue;
            }
            String registry = record.get(0).trim().toUpperCase(Locale.ROOT);
            String prefix = record.get(1).trim().toUpperCase(Locale.ROOT);
            String organization = record.get(2).trim().replaceAll("\s+", " ");
            Integer length = LENGTHS.get(registry);
            if (length == null || !prefix.matches("[0-9A-F]+") || prefix.length() * 4 != length
                    || organization.isEmpty()) {
                skipped++;
                continue;
            }
            if (organization.length() > MAX_ORGANIZATION) {
                organization = organization.substring(0, MAX_ORGANIZATION);
            }
            entries.add(new Entry(prefix, length, organization, registry));
        }
        return new Result(entries, skipped);
    }

    /** Next CSV record (fields may contain quoted commas, quotes and line breaks), null at the end. */
    private static List<String> next(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        while (line != null && line.isBlank()) {
            line = reader.readLine();
        }
        if (line == null) {
            return null;
        }
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        while (true) {
            for (int i = 0; i < line.length(); i++) {
                char ch = line.charAt(i);
                if (quoted) {
                    if (ch == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else if (ch == '"') {
                        quoted = false;
                    } else {
                        field.append(ch);
                    }
                } else if (ch == '"') {
                    quoted = true;
                } else if (ch == ',') {
                    fields.add(field.toString());
                    field.setLength(0);
                } else {
                    field.append(ch);
                }
            }
            if (!quoted) {
                break;
            }
            line = reader.readLine(); // a quoted field spanning lines
            if (line == null) {
                break;
            }
            field.append(' ');
        }
        fields.add(field.toString());
        return fields;
    }
}
