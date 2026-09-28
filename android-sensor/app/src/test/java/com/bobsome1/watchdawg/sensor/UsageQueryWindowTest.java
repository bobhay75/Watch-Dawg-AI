package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class UsageQueryWindowTest {
    private static final long HOUR = 60L * 60L * 1_000L;
    private static final long NOW = 10L * 24L * HOUR;

    @Test
    public void threeDayOldCursorReportsGapAndClampsToHorizon() {
        UsageQueryWindow window = UsageQueryWindow.resolve(
                true, NOW - 3L * 24L * HOUR, NOW, HOUR, 24L * HOUR);

        assertTrue(window.historyGap);
        assertEquals(NOW - 24L * HOUR, window.startMillis);
    }

    @Test
    public void exactHorizonAndRecentCursorHaveNoGap() {
        UsageQueryWindow boundary = UsageQueryWindow.resolve(
                true, NOW - 24L * HOUR, NOW, HOUR, 24L * HOUR);
        UsageQueryWindow recent = UsageQueryWindow.resolve(
                true, NOW - HOUR, NOW, HOUR, 24L * HOUR);

        assertFalse(boundary.historyGap);
        assertEquals(NOW - 24L * HOUR, boundary.startMillis);
        assertFalse(recent.historyGap);
        assertEquals(NOW - HOUR, recent.startMillis);
    }

    @Test
    public void firstScanIsBoundedInitializationNotAHistoryClaim() {
        UsageQueryWindow window = UsageQueryWindow.resolve(
                false, 0L, NOW, HOUR, 24L * HOUR);

        assertFalse(window.historyGap);
        assertEquals(NOW - HOUR, window.startMillis);
    }

    @Test
    public void futureCursorAfterClockRollbackReportsGap() {
        UsageQueryWindow window = UsageQueryWindow.resolve(
                true, NOW + 1L, NOW, HOUR, 24L * HOUR);

        assertTrue(window.historyGap);
        assertEquals(NOW - 24L * HOUR, window.startMillis);
    }
}
