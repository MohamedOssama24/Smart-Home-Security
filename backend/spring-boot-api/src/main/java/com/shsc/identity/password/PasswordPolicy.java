package com.shsc.identity.password;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.shsc.shared.web.ApiException;

/**
 * Password rules (NIST SP 800-63B style: length over composition rules):
 * 12–128 characters, not a known common password (local list, no external calls),
 * not trivially repetitive or sequential, not containing the e-mail name or display name.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;
    private static final int MIN_DISTINCT_CHARACTERS = 5;

    private final Set<String> commonPasswords;

    public PasswordPolicy() {
        this.commonPasswords = load("/security/common-passwords.txt");
    }

    /** Returns the list of violated rules (empty = valid). */
    public List<String> violations(String password, String email, String displayName) {
        List<String> violations = new ArrayList<>();
        if (password == null || password.codePointCount(0, password.length()) < MIN_LENGTH) {
            violations.add("PASSWORD_TOO_SHORT");
            return violations;
        }
        if (password.length() > MAX_LENGTH) {
            violations.add("PASSWORD_TOO_LONG");
            return violations;
        }
        String lower = password.toLowerCase(Locale.ROOT);
        if (commonPasswords.contains(lower)) {
            violations.add("PASSWORD_TOO_COMMON");
        }
        if (password.codePoints().distinct().count() < MIN_DISTINCT_CHARACTERS || isSequential(lower)) {
            violations.add("PASSWORD_TOO_SIMPLE");
        }
        if (containsPersonalData(lower, email, displayName)) {
            violations.add("PASSWORD_CONTAINS_PERSONAL_DATA");
        }
        return violations;
    }

    public void check(String password, String email, String displayName) {
        List<String> violations = violations(password, email, displayName);
        if (!violations.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "PASSWORD_POLICY",
                    "The password does not meet the security requirements.", Map.of("violations", violations));
        }
    }

    private static boolean containsPersonalData(String lowerPassword, String email, String displayName) {
        if (email != null) {
            String local = email.toLowerCase(Locale.ROOT);
            int at = local.indexOf('@');
            if (at > 0) {
                local = local.substring(0, at);
            }
            if (local.length() >= 4 && lowerPassword.contains(local)) {
                return true;
            }
        }
        if (displayName != null) {
            for (String part : displayName.toLowerCase(Locale.ROOT).split("\\s+")) {
                if (part.length() >= 4 && lowerPassword.contains(part)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True if every character differs from the previous one by the same step (-1, 0 or +1). */
    private static boolean isSequential(String value) {
        int[] cps = value.codePoints().toArray();
        int step = cps[1] - cps[0];
        if (Math.abs(step) > 1) {
            return false;
        }
        for (int i = 2; i < cps.length; i++) {
            if (cps[i] - cps[i - 1] != step) {
                return false;
            }
        }
        return true;
    }

    private static Set<String> load(String resource) {
        Set<String> values = new HashSet<>();
        try (InputStream in = PasswordPolicy.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing resource " + resource);
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    values.add(trimmed.toLowerCase(Locale.ROOT));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return Set.copyOf(values);
    }
}
