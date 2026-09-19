package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class UsageCheckpointTest {
    @Test
    public void completeQueryAdvancesToQueryEnd() {
        UsageCheckpoint checkpoint = UsageCheckpoint.restore(100L, 3L)
                .afterQuery(900L, false);

        assertEquals(900L, checkpoint.timestamp);
        assertEquals(0L, checkpoint.ordinal);
    }

    @Test
    public void truncatedQueryRetainsExactConsumedBoundary() {
        UsageCheckpoint checkpoint = UsageCheckpoint.restore(100L, 3L)
                .afterConsumed(500L, 17L)
                .afterQuery(900L, true);

        assertEquals(500L, checkpoint.timestamp);
        assertEquals(17L, checkpoint.ordinal);
    }

    @Test
    public void moreThanFiveHundredSameTimestampRowsMakeProgressAcrossPasses() {
        UsageCheckpoint checkpoint = UsageCheckpoint.restore(0L, 0L);
        long timestamp = 500L;

        checkpoint = consumeBatch(checkpoint, timestamp, 1_001L, 500);
        assertEquals(timestamp, checkpoint.timestamp);
        assertEquals(500L, checkpoint.ordinal);

        checkpoint = consumeBatch(checkpoint, timestamp, 1_001L, 500);
        assertEquals(timestamp, checkpoint.timestamp);
        assertEquals(1_000L, checkpoint.ordinal);

        checkpoint = consumeBatch(checkpoint, timestamp, 1_001L, 500)
                .afterQuery(900L, false);
        assertEquals(900L, checkpoint.timestamp);
        assertEquals(0L, checkpoint.ordinal);
    }

    @Test
    public void skipsOnlyPersistedPrefixAtBoundaryTimestamp() {
        UsageCheckpoint checkpoint = UsageCheckpoint.restore(500L, 500L);

        assertTrue(checkpoint.wasConsumed(499L, 1L));
        assertTrue(checkpoint.wasConsumed(500L, 500L));
        assertFalse(checkpoint.wasConsumed(500L, 501L));
        assertFalse(checkpoint.wasConsumed(501L, 1L));
        assertThrows(
                IllegalStateException.class,
                () -> checkpoint.afterConsumed(499L, 2L));
    }

    private static UsageCheckpoint consumeBatch(
            UsageCheckpoint checkpoint,
            long timestamp,
            long sourceRows,
            int capacity) {
        int consumedThisPass = 0;
        for (long ordinal = 1L; ordinal <= sourceRows; ordinal++) {
            if (checkpoint.wasConsumed(timestamp, ordinal)) {
                continue;
            }
            if (consumedThisPass == capacity) {
                return checkpoint.afterQuery(900L, true);
            }
            checkpoint = checkpoint.afterConsumed(timestamp, ordinal);
            consumedThisPass++;
        }
        return checkpoint;
    }
}
