package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class EditGenerationTest {
    @Test
    public void delayedOperationCannotClearNewerInput() {
        EditGeneration generation = new EditGeneration();
        long captured = generation.snapshot();
        assertTrue(generation.isCurrent(captured));

        generation.markChanged();
        assertFalse(generation.isCurrent(captured));
    }
}
