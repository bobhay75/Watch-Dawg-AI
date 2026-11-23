package com.bobsome1.watchdawg.sensor;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Pure policy helpers for owner-approved app inventory decisions. */
final class PhoneGuardDecision {
    private PhoneGuardDecision() {}

    static Set<String> unexpected(Set<String> approved, Set<String> installed) {
        Set<String> result = new TreeSet<>(installed == null
                ? Collections.emptySet() : installed);
        result.removeAll(approved == null ? Collections.emptySet() : approved);
        return result;
    }

    static Set<String> pendingAlerts(
            Set<String> unexpected,
            Set<String> alreadyAlerted,
            int limit) {
        if (limit <= 0) {
            return Collections.emptySet();
        }
        Set<String> result = new TreeSet<>(unexpected == null
                ? Collections.emptySet() : unexpected);
        result.removeAll(alreadyAlerted == null
                ? Collections.emptySet() : alreadyAlerted);
        if (result.size() <= limit) {
            return result;
        }
        Set<String> limited = new TreeSet<>();
        for (String packageName : result) {
            limited.add(packageName);
            if (limited.size() >= limit) {
                break;
            }
        }
        return limited;
    }
}
