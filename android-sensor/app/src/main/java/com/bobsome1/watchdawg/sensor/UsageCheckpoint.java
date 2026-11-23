package com.bobsome1.watchdawg.sensor;

/** Loss-safe UsageStats cursor: timestamp plus consumed source-row ordinal. */
final class UsageCheckpoint {
    final long timestamp;
    final long ordinal;

    private UsageCheckpoint(long timestamp, long ordinal) {
        this.timestamp = timestamp;
        this.ordinal = ordinal;
    }

    static UsageCheckpoint restore(long timestamp, long ordinal) {
        if (timestamp < 0L || ordinal < 0L) {
            throw new IllegalStateException("UsageStats cursor is invalid");
        }
        return new UsageCheckpoint(timestamp, ordinal);
    }

    boolean wasConsumed(long eventTimestamp, long eventOrdinal) {
        if (eventTimestamp < 0L || eventOrdinal < 1L) {
            throw new IllegalArgumentException("UsageStats source position is invalid");
        }
        return eventTimestamp < timestamp
                || (eventTimestamp == timestamp && eventOrdinal <= ordinal);
    }

    UsageCheckpoint afterConsumed(long eventTimestamp, long eventOrdinal) {
        if (eventTimestamp < 0L || eventOrdinal < 1L) {
            throw new IllegalArgumentException("UsageStats source position is invalid");
        }
        if (eventTimestamp < timestamp) {
            throw new IllegalStateException("UsageStats events were not time ordered");
        }
        if (eventTimestamp == timestamp) {
            if (eventOrdinal <= ordinal) {
                throw new IllegalStateException("UsageStats source position was already consumed");
            }
            return new UsageCheckpoint(timestamp, eventOrdinal);
        }
        return new UsageCheckpoint(eventTimestamp, eventOrdinal);
    }

    UsageCheckpoint afterQuery(long queryEndTimestamp, boolean truncated) {
        if (queryEndTimestamp < timestamp) {
            throw new IllegalStateException("UsageStats query end precedes its cursor");
        }
        if (truncated || queryEndTimestamp == timestamp) {
            return this;
        }
        return new UsageCheckpoint(queryEndTimestamp, 0L);
    }
}
