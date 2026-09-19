package com.bobsome1.watchdawg.sensor;

import java.time.LocalDate;

/** Normalizes platform-owned strings to the signed schema's conservative grammar. */
final class MetadataNormalizer {
    private static final String UNKNOWN = "unknown";

    private MetadataNormalizer() {}

    static String securityPatch(String rawValue) {
        if (rawValue == null) {
            return UNKNOWN;
        }
        String value = rawValue.trim();
        if (value.length() != 10) {
            return UNKNOWN;
        }
        try {
            LocalDate.parse(value);
            return value;
        } catch (RuntimeException invalid) {
            return UNKNOWN;
        }
    }

    static String appVersion(String rawValue) {
        if (rawValue == null || rawValue.isEmpty() || rawValue.length() > 64) {
            return UNKNOWN;
        }
        for (int index = 0; index < rawValue.length(); index++) {
            char character = rawValue.charAt(index);
            boolean alphaNumeric = (character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9');
            boolean allowedPunctuation = index > 0
                    && (character == '.'
                    || character == '_'
                    || character == '+'
                    || character == '-');
            if (!alphaNumeric && !allowedPunctuation) {
                return UNKNOWN;
            }
        }
        return rawValue;
    }
}
