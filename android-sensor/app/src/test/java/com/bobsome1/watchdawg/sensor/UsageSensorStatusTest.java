package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class UsageSensorStatusTest {
    @Test
    public void reportsObservedOnlyAfterARealQueryCursorWasAvailable() {
        assertEquals("not_granted", UsageSensorStatus.resolve(false, false, false));
        assertEquals("not_granted", UsageSensorStatus.resolve(false, true, true));
        assertEquals("error", UsageSensorStatus.resolve(true, false, true));
        assertEquals("partial", UsageSensorStatus.resolve(true, true, false));
        assertEquals("observed", UsageSensorStatus.resolve(true, true, true));
    }
}
