package com.bobsome1.watchdawg.sensor;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/** Conservative, collection-time interpretation of Android's patch metadata. */
final class SecurityPatchStatus {
    private static final String UNKNOWN = "unknown";

    final String value;
    final long ageDays;

    private SecurityPatchStatus(String value, long ageDays) {
        this.value = value;
        this.ageDays = ageDays;
    }

    static SecurityPatchStatus from(String rawValue, LocalDate collectionDate) {
        if (collectionDate == null) {
            throw new NullPointerException("collectionDate");
        }
        String normalized = MetadataNormalizer.securityPatch(rawValue);
        if (UNKNOWN.equals(normalized)) {
            return unknown();
        }
        LocalDate patchDate = LocalDate.parse(normalized);
        if (patchDate.isAfter(collectionDate)) {
            // A future platform patch date contradicts the signed collection time.
            return unknown();
        }
        return new SecurityPatchStatus(
                normalized,
                ChronoUnit.DAYS.between(patchDate, collectionDate));
    }

    boolean isCurrent(long maximumAgeDays) {
        if (maximumAgeDays < 0L) {
            throw new IllegalArgumentException("maximumAgeDays must not be negative");
        }
        return ageDays >= 0L && ageDays <= maximumAgeDays;
    }

    private static SecurityPatchStatus unknown() {
        return new SecurityPatchStatus(UNKNOWN, -1L);
    }
}
