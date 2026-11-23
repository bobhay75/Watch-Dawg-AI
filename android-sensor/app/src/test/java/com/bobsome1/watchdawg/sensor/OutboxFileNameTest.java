package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public final class OutboxFileNameTest {
    private static final String A = "a".repeat(64);
    private static final String B = "b".repeat(64);

    @Test
    public void formatsAndParsesBoundarySequences() {
        String first = OutboxFileName.format(1L, A);
        assertEquals("0000000000000000001-" + A + ".json", first);
        assertEquals(1L, OutboxFileName.parse(first).sequence);

        String last = OutboxFileName.format(Long.MAX_VALUE, B);
        assertEquals(Long.MAX_VALUE, OutboxFileName.parse(last).sequence);
    }

    @Test
    public void ordersNumericallyAndIgnoresOnlyValidTemporaryFiles() {
        String one = OutboxFileName.format(1L, A);
        String ten = OutboxFileName.format(10L, B);
        List<OutboxFileName.Entry> ordered = OutboxFileName.ordered(
                Arrays.asList(ten, one + ".tmp", one));
        assertEquals(2, ordered.size());
        assertEquals(1L, ordered.get(0).sequence);
        assertEquals(10L, ordered.get(1).sequence);
    }

    @Test
    public void rejectsMalformedTraversalAndSequenceConflicts() {
        assertNull(OutboxFileName.parse("../" + OutboxFileName.format(1L, A)));
        assertNull(OutboxFileName.parse(OutboxFileName.format(1L, A).toUpperCase()));
        assertThrows(
                IllegalArgumentException.class,
                () -> OutboxFileName.ordered(Arrays.asList(
                        OutboxFileName.format(7L, A),
                        OutboxFileName.format(7L, B))));
    }
}
