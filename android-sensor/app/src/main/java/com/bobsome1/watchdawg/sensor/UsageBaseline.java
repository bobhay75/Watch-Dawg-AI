package com.bobsome1.watchdawg.sensor;

/** Tracks whether a complete successful UsageStats baseline has ever finished. */
final class UsageBaseline {
    private UsageBaseline() {}

    static boolean wasReady(
            boolean hasExplicitState,
            boolean explicitState,
            boolean hasLegacySuccessfulQueryWatermark) {
        return hasExplicitState ? explicitState : hasLegacySuccessfulQueryWatermark;
    }

    static boolean afterQuery(
            boolean wasReady, boolean queryComplete, boolean historyGap) {
        return wasReady || (queryComplete && !historyGap);
    }
}
