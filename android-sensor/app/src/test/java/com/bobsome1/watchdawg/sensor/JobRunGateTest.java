package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class JobRunGateTest {
    @Test
    public void stoppedRunCannotCompleteOrAffectReplacement() {
        JobRunGate gate = new JobRunGate();
        long stopped = gate.open();

        assertTrue(gate.stop(stopped));
        assertFalse(gate.complete(stopped));

        long replacement = gate.open();
        assertNotEquals(stopped, replacement);
        assertTrue(gate.isActive(replacement));
        assertFalse(gate.stop(stopped));
        assertTrue(gate.complete(replacement));
    }

    @Test
    public void onlyOneRunMayBeOpen() {
        JobRunGate gate = new JobRunGate();
        gate.open();

        assertThrows(IllegalStateException.class, gate::open);
    }
}
