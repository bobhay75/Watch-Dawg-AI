package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class UsageBaselineTest {
    @Test
    public void emptyButCompleteFirstQueryInitializesBaseline() {
        assertTrue(UsageBaseline.afterQuery(false, true, false));
    }

    @Test
    public void partialFirstQueryDoesNotInitializeBaseline() {
        assertFalse(UsageBaseline.afterQuery(false, false, false));
    }

    @Test
    public void establishedBaselineNeverRegresses() {
        assertTrue(UsageBaseline.afterQuery(true, false, false));
    }

    @Test
    public void boundedQueryAfterHistoryGapDoesNotInitializeBaseline() {
        assertFalse(UsageBaseline.afterQuery(false, true, true));
        assertTrue(UsageBaseline.afterQuery(true, true, true));
    }

    @Test
    public void explicitPartialStateOverridesLegacyTimestampPresence() {
        assertFalse(UsageBaseline.wasReady(true, false, true));
        assertTrue(UsageBaseline.wasReady(true, true, true));
    }

    @Test
    public void oldInstallCanMigrateFromSuccessfulQueryTimestamp() {
        assertTrue(UsageBaseline.wasReady(false, false, true));
        assertFalse(UsageBaseline.wasReady(false, false, false));
    }
}
