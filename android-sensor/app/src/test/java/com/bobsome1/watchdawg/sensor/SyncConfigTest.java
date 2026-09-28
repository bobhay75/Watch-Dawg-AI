package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class SyncConfigTest {
    @Test
    public void acceptsOnlyUrlSafeAsciiAtSupportedLengths() {
        assertTrue(SyncConfig.isValidToken("A2345678901234567890123456789012"));
        assertTrue(SyncConfig.isValidToken(repeat("Ab9_-", 51) + "Z"));
    }

    @Test
    public void rejectsMissingOrOutOfRangeTokens() {
        assertFalse(SyncConfig.isValidToken(null));
        assertFalse(SyncConfig.isValidToken(""));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31)));
        assertFalse(SyncConfig.isValidToken(repeat("a", 257)));
    }

    @Test
    public void rejectsWhitespacePunctuationAndNonAscii() {
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + " "));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "\n"));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "."));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "+"));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "/"));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "="));
        assertFalse(SyncConfig.isValidToken(repeat("a", 31) + "é"));
    }

    private static String repeat(String value, int count) {
        return value.repeat(count);
    }
}
