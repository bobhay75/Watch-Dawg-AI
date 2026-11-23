package com.bobsome1.watchdawg.sensor;

/** Pure queue capacity, sequence, and acknowledgement invariants. */
final class OutboxPolicy {
    static final int MAX_PENDING = 32;

    private OutboxPolicy() {}

    static boolean isFull(int pendingCount) {
        if (pendingCount < 0) {
            throw new IllegalArgumentException("pendingCount must not be negative");
        }
        return pendingCount >= MAX_PENDING;
    }

    static long nextSequence(long storedSequence, long highestDurableSequence) {
        long current = Math.max(storedSequence, highestDurableSequence);
        if (current < 0L || current == Long.MAX_VALUE) {
            throw new IllegalStateException("Snapshot sequence is invalid or exhausted");
        }
        return current + 1L;
    }

    static boolean ackMatches(
            long expectedSequence,
            String expectedPayloadSha256,
            long actualSequence,
            String actualPayloadSha256) {
        return expectedSequence == actualSequence
                && expectedPayloadSha256.equals(actualPayloadSha256);
    }
}
