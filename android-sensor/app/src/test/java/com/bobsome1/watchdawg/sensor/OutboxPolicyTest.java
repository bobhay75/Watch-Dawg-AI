package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class OutboxPolicyTest {
    @Test
    public void capacityNeverEvictsPendingEvidence() {
        assertFalse(OutboxPolicy.isFull(31));
        assertTrue(OutboxPolicy.isFull(32));
        assertTrue(OutboxPolicy.isFull(33));
    }

    @Test
    public void recoversNextSequenceFromHighestDurableSource() {
        assertEquals(8L, OutboxPolicy.nextSequence(7L, 3L));
        assertEquals(9L, OutboxPolicy.nextSequence(2L, 8L));
        assertThrows(
                IllegalStateException.class,
                () -> OutboxPolicy.nextSequence(1L, Long.MAX_VALUE));
    }

    @Test
    public void acknowledgementMustMatchExactQueuedIdentity() {
        assertTrue(OutboxPolicy.ackMatches(7L, "hash-a", 7L, "hash-a"));
        assertFalse(OutboxPolicy.ackMatches(7L, "hash-a", 8L, "hash-a"));
        assertFalse(OutboxPolicy.ackMatches(7L, "hash-a", 7L, "hash-b"));
    }
}
