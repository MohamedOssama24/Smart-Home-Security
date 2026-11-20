package com.shsc.people;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Finds the name of a person in the name a device announces (M24, ADR-081), only in the two
 * forms that phones, tablets and computers create by default:
 * <ul>
 * <li>owner after the device: "iPhone-di-Marco", "Galaxy-S21-di-Giulia", "MacBook Pro of Anna";</li>
 * <li>owner before the device: "Marcos-iPhone" (Apple turns "Marco's iPhone" into it), "Luca-PC".</li>
 * </ul>
 * A device word is always required next to the name, and generic words (android, desktop,
 * admin, ...) are never names: "DESKTOP-AB12CD3" or "Android_3" give nothing. The result is
 * only probable: it is shown with the name it comes from and the user can reject it.
 */
public final class PersonNames {

    private static final Pattern SPLIT = Pattern.compile("[-_.\\s'’]+");
    private static final Pattern WORD = Pattern.compile("^\\p{L}{2,20}$");
    private static final Set<String> DEVICES = Set.of("iphone", "ipad", "ipod", "macbook", "mbp", "mba", "imac",
            "mac", "macmini", "watch", "applewatch", "airpods", "galaxy", "pixel", "redmi", "xiaomi", "huawei", "oppo",
            "oneplus", "honor", "motorola", "moto", "nokia", "realme", "vivo", "telefono", "cellulare", "smartphone",
            "phone", "tablet", "pc", "laptop", "notebook", "portatile", "computer", "surface", "kindle", "thinkpad",
            "chromebook", "fisso");
    /** Device words Apple uses in "Name's Device": the "s" before them is the possessive. */
    private static final Set<String> APPLE = Set.of("iphone", "ipad", "ipod", "macbook", "mbp", "mba", "imac", "mac",
            "macmini", "watch", "applewatch", "airpods");
    private static final Set<String> OF = Set.of("di", "de", "del", "della", "of", "von", "du", "da");
    private static final Set<String> NOT_NAMES = Set.of("android", "desktop", "laptop", "user", "utente", "admin",
            "administrator", "guest", "ospite", "home", "casa", "ufficio", "office", "server", "my", "mio", "mia",
            "the", "new", "nuovo", "old", "vecchio", "work", "lavoro", "test", "personal", "personale", "pro", "air",
            "max", "plus", "mini", "ultra", "lite", "note", "edge", "fold", "flip", "se", "win", "windows", "linux",
            "wifi", "lan", "local", "localdomain", "domain", "default", "unknown", "sconosciuto", "family",
            "famiglia", "kids", "bambini", "sala", "camera", "cucina", "soggiorno", "studio", "reception");

    public record Found(String name, String evidence) {
    }

    private PersonNames() {
    }

    public static Optional<Found> find(String deviceName) {
        if (deviceName == null || deviceName.isBlank() || deviceName.length() > 100) {
            return Optional.empty();
        }
        String text = Normalizer.normalize(deviceName.trim(), Normalizer.Form.NFC);
        String first = text.split("\\.", 2)[0]; // "Marcos-iPhone.local" -> "Marcos-iPhone"
        List<String> tokens = new ArrayList<>();
        for (String t : SPLIT.split(first)) {
            if (!t.isEmpty()) {
                tokens.add(t);
            }
        }
        if (tokens.size() < 2) {
            return Optional.empty();
        }
        Optional<String> name = after(tokens).or(() -> before(tokens));
        return name.map(n -> new Found(n, text.length() > 255 ? text.substring(0, 255) : text));
    }

    /** "iPhone-di-Marco[-Rossi]": a device word, then "di"/"of", then one or two name words at the end. */
    private static Optional<String> after(List<String> tokens) {
        for (int i = 1; i < tokens.size() - 1; i++) {
            if (!OF.contains(lower(tokens.get(i))) || tokens.subList(0, i).stream().noneMatch(PersonNames::isDevice)) {
                continue;
            }
            List<String> rest = tokens.subList(i + 1, tokens.size());
            if (rest.size() > 2 || !rest.stream().allMatch(PersonNames::isName)) {
                return Optional.empty();
            }
            return Optional.of(String.join(" ", rest.stream().map(PersonNames::capitalize).toList()));
        }
        return Optional.empty();
    }

    /** "Marcos-iPhone", "Luca-PC": a name word followed by a device word. */
    private static Optional<String> before(List<String> tokens) {
        String first = tokens.get(0);
        String second = lower(tokens.get(1));
        if (tokens.size() >= 3 && "s".equals(second) && isDevice(tokens.get(2))) {
            second = lower(tokens.get(2)); // "Marco's iPhone" split on the apostrophe
        } else if (!isDevice(second)) {
            return Optional.empty();
        } else if (APPLE.contains(second) && first.length() > 3 && lower(first).endsWith("s")) {
            first = first.substring(0, first.length() - 1);
        }
        return isName(first) ? Optional.of(capitalize(first)) : Optional.empty();
    }

    private static boolean isDevice(String token) {
        return DEVICES.contains(lower(token));
    }

    private static boolean isName(String token) {
        String l = lower(token);
        return WORD.matcher(token).matches() && !DEVICES.contains(l) && !NOT_NAMES.contains(l) && !OF.contains(l);
    }

    private static String lower(String s) {
        return s.toLowerCase(Locale.ROOT);
    }

    private static String capitalize(String s) {
        String l = lower(s);
        return l.substring(0, 1).toUpperCase(Locale.ROOT) + l.substring(1);
    }
}
