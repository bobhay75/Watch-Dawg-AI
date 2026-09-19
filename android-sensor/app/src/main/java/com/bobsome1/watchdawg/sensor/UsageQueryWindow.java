package com.bobsome1.watchdawg.sensor;

/** Selects a bounded UsageStats window without hiding an unobserved interval. */
final class UsageQueryWindow {
    final long startMillis;
    final boolean historyGap;

    private UsageQueryWindow(long startMillis, boolean historyGap) {
        this.startMillis = startMillis;
        this.historyGap = historyGap;
    }

    static UsageQueryWindow resolve(
            boolean hasCheckpoint,
            long checkpointMillis,
            long nowMillis,
            long firstScanWindowMillis,
            long maximumWindowMillis) {
        if (nowMillis < 0L
                || checkpointMillis < 0L
                || firstScanWindowMillis < 0L
                || maximumWindowMillis < firstScanWindowMillis) {
            throw new IllegalArgumentException("UsageStats window inputs are invalid");
        }
        long horizon = Math.max(0L, nowMillis - maximumWindowMillis);
        if (!hasCheckpoint) {
            return new UsageQueryWindow(
                    Math.max(0L, nowMillis - firstScanWindowMillis), false);
        }
        if (checkpointMillis < horizon || checkpointMillis > nowMillis) {
            return new UsageQueryWindow(horizon, true);
        }
        return new UsageQueryWindow(checkpointMillis, false);
    }
}
