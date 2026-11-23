package com.bobsome1.watchdawg.sensor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Small deterministic JSON encoder used by both collection and signing.
 *
 * <p>The Watch-Dawg v1 profile permits objects with string keys, arrays,
 * strings, booleans, null, and integral numbers. Floating-point numbers are
 * deliberately rejected so two implementations cannot disagree about their
 * textual representation.</p>
 */
public final class CanonicalJson {
    private CanonicalJson() {}

    public static String encode(Object value) {
        StringBuilder output = new StringBuilder();
        appendValue(output, value);
        return output.toString();
    }

    private static void appendValue(StringBuilder output, Object value) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String) {
            appendString(output, (String) value);
        } else if (value instanceof Boolean) {
            output.append(value);
        } else if (value instanceof Byte
                || value instanceof Short
                || value instanceof Integer
                || value instanceof Long
                || value instanceof BigInteger) {
            output.append(value);
        } else if (value instanceof Map<?, ?>) {
            appendMap(output, (Map<?, ?>) value);
        } else if (value instanceof List<?>) {
            appendList(output, (List<?>) value);
        } else {
            throw new IllegalArgumentException(
                    "Unsupported canonical JSON type: " + value.getClass().getName());
        }
    }

    private static void appendMap(StringBuilder output, Map<?, ?> value) {
        List<String> keys = new ArrayList<>();
        for (Object key : value.keySet()) {
            if (!(key instanceof String)) {
                throw new IllegalArgumentException("Canonical JSON object keys must be strings");
            }
            keys.add((String) key);
        }
        Collections.sort(keys);

        output.append('{');
        boolean first = true;
        for (String key : keys) {
            if (!first) {
                output.append(',');
            }
            first = false;
            appendString(output, key);
            output.append(':');
            appendValue(output, value.get(key));
        }
        output.append('}');
    }

    private static void appendList(StringBuilder output, List<?> value) {
        output.append('[');
        for (int index = 0; index < value.size(); index++) {
            if (index > 0) {
                output.append(',');
            }
            appendValue(output, value.get(index));
        }
        output.append(']');
    }

    private static void appendString(StringBuilder output, String value) {
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    output.append("\\\"");
                    break;
                case '\\':
                    output.append("\\\\");
                    break;
                case '\b':
                    output.append("\\b");
                    break;
                case '\f':
                    output.append("\\f");
                    break;
                case '\n':
                    output.append("\\n");
                    break;
                case '\r':
                    output.append("\\r");
                    break;
                case '\t':
                    output.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        appendUnicodeEscape(output, character);
                    } else if (Character.isHighSurrogate(character)) {
                        if (index + 1 >= value.length()
                                || !Character.isLowSurrogate(value.charAt(index + 1))) {
                            throw new IllegalArgumentException("Unpaired high surrogate in JSON string");
                        }
                        output.append(character);
                        output.append(value.charAt(++index));
                    } else if (Character.isLowSurrogate(character)) {
                        throw new IllegalArgumentException("Unpaired low surrogate in JSON string");
                    } else {
                        output.append(character);
                    }
            }
        }
        output.append('"');
    }

    private static void appendUnicodeEscape(StringBuilder output, char value) {
        final char[] hexadecimal = "0123456789abcdef".toCharArray();
        output.append("\\u");
        output.append(hexadecimal[(value >>> 12) & 0x0f]);
        output.append(hexadecimal[(value >>> 8) & 0x0f]);
        output.append(hexadecimal[(value >>> 4) & 0x0f]);
        output.append(hexadecimal[value & 0x0f]);
    }
}
