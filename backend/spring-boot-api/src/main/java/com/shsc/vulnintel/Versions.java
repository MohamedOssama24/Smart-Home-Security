package com.shsc.vulnintel;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Version comparison for CPE ranges. Versions are split into numeric and alphabetic tokens
 * ("9.6p1" → 9, 6, p, 1): numbers compare numerically, words alphabetically, a number is
 * newer than a word, and a missing token is older ("9.6" &lt; "9.6p1", the OpenSSH patch
 * release). Only well-formed versions starting with a digit are compared: anything else is
 * "version unknown" and can never produce a version match.
 */
public final class Versions {

    private static final Pattern VALID = Pattern.compile("[0-9][0-9A-Za-z._+~-]{0,31}");

    private Versions() {
    }

    public static boolean comparable(String version) {
        return version != null && VALID.matcher(version).matches();
    }

    /** Negative, zero or positive like {@link Comparable}; both versions must be {@link #comparable}. */
    public static int compare(String a, String b) {
        List<String> x = tokens(a);
        List<String> y = tokens(b);
        for (int i = 0; i < Math.max(x.size(), y.size()); i++) {
            if (i >= x.size()) {
                return -1;
            }
            if (i >= y.size()) {
                return 1;
            }
            int c = compareToken(x.get(i), y.get(i));
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    /**
     * Whether {@code version} is {@code base} or a variant of it ("9.6p1" of "9.6", not "9.61"):
     * used for CPE criteria whose update field is a wildcard.
     */
    public static boolean sameRelease(String version, String base) {
        if (!version.toLowerCase(Locale.ROOT).startsWith(base.toLowerCase(Locale.ROOT))) {
            return false;
        }
        if (version.length() == base.length()) {
            return true;
        }
        char next = version.charAt(base.length());
        return !Character.isDigit(next) && next != '.';
    }

    private static int compareToken(String a, String b) {
        boolean na = Character.isDigit(a.charAt(0));
        boolean nb = Character.isDigit(b.charAt(0));
        if (na && nb) {
            String x = a.replaceFirst("^0+(?=.)", "");
            String y = b.replaceFirst("^0+(?=.)", "");
            return x.length() != y.length() ? Integer.compare(x.length(), y.length()) : x.compareTo(y);
        }
        if (na != nb) {
            return na ? 1 : -1;
        }
        return a.toLowerCase(Locale.ROOT).compareTo(b.toLowerCase(Locale.ROOT));
    }

    private static List<String> tokens(String version) {
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (char ch : version.toCharArray()) {
            boolean separator = !Character.isLetterOrDigit(ch);
            if (separator || current.length() > 0
                    && Character.isDigit(ch) != Character.isDigit(current.charAt(current.length() - 1))) {
                if (current.length() > 0) {
                    out.add(current.toString());
                    current.setLength(0);
                }
            }
            if (!separator) {
                current.append(ch);
            }
        }
        if (current.length() > 0) {
            out.add(current.toString());
        }
        return out;
    }
}
