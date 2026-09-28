package com.bobsome1.watchdawg.sensor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/** Strict, numeric ordering for immutable outbox entry names. */
final class OutboxFileName {
    private static final int SEQUENCE_DIGITS = 19;
    private static final int SHA256_HEX_DIGITS = 64;
    private static final String SUFFIX = ".json";
    private static final String TEMP_SUFFIX = ".tmp";

    private OutboxFileName() {}

    static String format(long sequence, String payloadSha256) {
        if (sequence < 1L || !isLowerHexSha256(payloadSha256)) {
            throw new IllegalArgumentException("Invalid outbox identity");
        }
        return String.format(
                Locale.ROOT, "%019d-%s%s", sequence, payloadSha256, SUFFIX);
    }

    static List<Entry> ordered(Collection<String> fileNames) {
        Map<Long, Entry> bySequence = new TreeMap<>();
        for (String fileName : fileNames) {
            if (fileName.endsWith(TEMP_SUFFIX)) {
                String baseName = fileName.substring(
                        0, fileName.length() - TEMP_SUFFIX.length());
                if (parse(baseName) == null) {
                    throw new IllegalArgumentException("Malformed outbox temporary file");
                }
                continue;
            }
            Entry parsed = parse(fileName);
            if (parsed == null) {
                throw new IllegalArgumentException("Unexpected file in snapshot outbox");
            }
            Entry existing = bySequence.putIfAbsent(parsed.sequence, parsed);
            if (existing != null
                    && !existing.payloadSha256.equals(parsed.payloadSha256)) {
                throw new IllegalArgumentException(
                        "Conflicting payloads share one outbox sequence");
            }
        }
        return new ArrayList<>(bySequence.values());
    }

    static Entry parse(String fileName) {
        int expectedLength = SEQUENCE_DIGITS + 1 + SHA256_HEX_DIGITS + SUFFIX.length();
        if (fileName == null
                || fileName.length() != expectedLength
                || fileName.charAt(SEQUENCE_DIGITS) != '-'
                || !fileName.endsWith(SUFFIX)) {
            return null;
        }
        for (int index = 0; index < SEQUENCE_DIGITS; index++) {
            char character = fileName.charAt(index);
            if (character < '0' || character > '9') {
                return null;
            }
        }
        String digest = fileName.substring(
                SEQUENCE_DIGITS + 1, SEQUENCE_DIGITS + 1 + SHA256_HEX_DIGITS);
        if (!isLowerHexSha256(digest)) {
            return null;
        }
        try {
            long sequence = Long.parseLong(fileName.substring(0, SEQUENCE_DIGITS));
            return sequence < 1L ? null : new Entry(sequence, digest, fileName);
        } catch (NumberFormatException invalid) {
            return null;
        }
    }

    private static boolean isLowerHexSha256(String value) {
        if (value == null || value.length() != SHA256_HEX_DIGITS) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    static final class Entry {
        final long sequence;
        final String payloadSha256;
        final String fileName;

        private Entry(long sequence, String payloadSha256, String fileName) {
            this.sequence = sequence;
            this.payloadSha256 = payloadSha256;
            this.fileName = fileName;
        }
    }
}
