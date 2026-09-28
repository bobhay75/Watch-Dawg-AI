package com.bobsome1.watchdawg.sensor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Linear-time indexes for persisted package and permission baseline entries. */
final class CollectionStateIndex {
    private CollectionStateIndex() {}

    static Map<String, String> inventory(Set<String> entries) {
        Map<String, String> indexed = new HashMap<>();
        for (String entry : entries) {
            int separator = entry.lastIndexOf('|');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw new IllegalStateException("Stored package baseline is malformed");
            }
            putUnique(indexed, entry.substring(0, separator), entry);
        }
        return indexed;
    }

    static PermissionIndex permissions(Set<String> entries) {
        Map<String, String> indexed = new HashMap<>();
        Map<String, List<String>> byPackage = new HashMap<>();
        for (String entry : entries) {
            int lastSeparator = entry.lastIndexOf('|');
            int firstSeparator = entry.indexOf('|');
            if (firstSeparator <= 0
                    || lastSeparator <= firstSeparator
                    || lastSeparator == entry.length() - 1) {
                throw new IllegalStateException("Stored permission baseline is malformed");
            }
            putUnique(indexed, entry.substring(0, lastSeparator), entry);
            byPackage.computeIfAbsent(
                    entry.substring(0, firstSeparator), ignored -> new ArrayList<>())
                    .add(entry);
        }
        return new PermissionIndex(indexed, byPackage);
    }

    private static void putUnique(
            Map<String, String> indexed, String key, String entry) {
        String prior = indexed.putIfAbsent(key, entry);
        if (prior != null && !prior.equals(entry)) {
            throw new IllegalStateException("Stored collection baseline has conflicting entries");
        }
    }

    static final class PermissionIndex {
        private final Map<String, String> entries;
        private final Map<String, List<String>> byPackage;

        private PermissionIndex(
                Map<String, String> entries,
                Map<String, List<String>> byPackage) {
            this.entries = entries;
            this.byPackage = byPackage;
        }

        String get(String packageHash, String permission) {
            return entries.get(packageHash + "|" + permission);
        }

        List<String> forPackage(String packageHash) {
            List<String> values = byPackage.get(packageHash);
            return values == null ? Collections.emptyList() : values;
        }
    }
}
