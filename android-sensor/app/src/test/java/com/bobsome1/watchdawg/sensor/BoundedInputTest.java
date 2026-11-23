package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class BoundedInputTest {
    @Test
    public void acceptsInputAtTheExactLimit() throws Exception {
        byte[] input = "exact".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(
                input,
                BoundedInput.read(new ByteArrayInputStream(input), input.length));
    }

    @Test
    public void rejectsTheFirstBytePastTheLimit() {
        byte[] input = "too-long".getBytes(StandardCharsets.UTF_8);
        assertThrows(
                IllegalStateException.class,
                () -> BoundedInput.read(
                        new ByteArrayInputStream(input), input.length - 1));
    }

    @Test
    public void acceptsAnEmptyZeroLimitStream() throws Exception {
        assertArrayEquals(
                new byte[0],
                BoundedInput.read(new ByteArrayInputStream(new byte[0]), 0));
    }
}
