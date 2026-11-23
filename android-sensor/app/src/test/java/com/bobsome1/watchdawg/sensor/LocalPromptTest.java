package com.bobsome1.watchdawg.sensor;

import org.junit.Test;
import static org.junit.Assert.*;

public final class LocalPromptTest {
    @Test public void acceptsExactBoundAndRejectsOversizedDirectRequests() {
        String maximum = new String(new char[LocalPrompt.MAX_CHARS]).replace('\0', 'x');
        assertEquals(maximum, LocalPrompt.validate(maximum));
        assertThrows(IllegalArgumentException.class, () -> LocalPrompt.validate(maximum + "x"));
    }

    @Test public void rejectsBlankAndTrimsValidQuestions() {
        assertThrows(IllegalArgumentException.class, () -> LocalPrompt.validate(" \n\t "));
        assertEquals("Where is the kit?", LocalPrompt.validate("  Where is the kit?\n"));
    }
}
