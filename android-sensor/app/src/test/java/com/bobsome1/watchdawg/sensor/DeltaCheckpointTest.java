package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class DeltaCheckpointTest {
    @Test
    public void advancesAfterEvidenceWasEmitted() {
        assertEquals("new", DeltaCheckpoint.select("old", "new", true, true));
    }

    @Test
    public void retainsPriorValueWhileEvidenceIsTruncated() {
        assertEquals("old", DeltaCheckpoint.select("old", "new", true, false));
    }

    @Test
    public void leavesNewItemUncheckpointedWhileItsEvidenceIsTruncated() {
        assertNull(DeltaCheckpoint.select(null, "new", true, false));
    }

    @Test
    public void baselineInitializationDoesNotRequireDeltaEvidence() {
        assertEquals("new", DeltaCheckpoint.select(null, "new", false, false));
    }
}
