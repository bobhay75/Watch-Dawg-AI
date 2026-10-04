package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.LocalDate;
import org.junit.Test;

public final class SecurityPatchStatusTest {
    private static final LocalDate COLLECTED_ON = LocalDate.of(2026, 9, 17);

    @Test
    public void computesAgeAgainstSignedCollectionDate() {
        SecurityPatchStatus status = SecurityPatchStatus.from(
                "2026-09-01", COLLECTED_ON);

        assertEquals("2026-09-01", status.value);
        assertEquals(16L, status.ageDays);
        assertTrue(status.isCurrent(120L));
    }

    @Test
    public void futurePatchDateIsUnknownAndNeverCurrent() {
        SecurityPatchStatus status = SecurityPatchStatus.from(
                "2026-09-18", COLLECTED_ON);

        assertEquals("unknown", status.value);
        assertEquals(-1L, status.ageDays);
        assertFalse(status.isCurrent(120L));
    }

    @Test
    public void malformedOrOldPatchIsNotCurrent() {
        SecurityPatchStatus malformed = SecurityPatchStatus.from(
                "not-a-date", COLLECTED_ON);
        SecurityPatchStatus old = SecurityPatchStatus.from(
                "2025-01-01", COLLECTED_ON);

        assertEquals("unknown", malformed.value);
        assertEquals(-1L, malformed.ageDays);
        assertFalse(malformed.isCurrent(120L));
        assertFalse(old.isCurrent(120L));
    }
}
