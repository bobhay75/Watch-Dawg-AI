package com.bobsome1.watchdawg.sensor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Reads a stream while using one look-ahead byte to enforce an exact size cap. */
final class BoundedInput {
    private static final int BUFFER_BYTES = 8_192;

    private BoundedInput() {}

    static byte[] read(InputStream input, int maxBytes) throws IOException {
        if (input == null) {
            throw new NullPointerException("input");
        }
        if (maxBytes < 0) {
            throw new IllegalArgumentException("maxBytes must not be negative");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                Math.min(maxBytes, BUFFER_BYTES));
        byte[] buffer = new byte[(int) Math.min(
                BUFFER_BYTES, (long) maxBytes + 1L)];
        int total = 0;
        while (true) {
            int remainingWithLookAhead = maxBytes - total + 1;
            int count = input.read(
                    buffer, 0, Math.min(buffer.length, remainingWithLookAhead));
            if (count < 0) {
                return output.toByteArray();
            }
            if (count == 0) {
                continue;
            }
            if (count > maxBytes - total) {
                throw new IllegalStateException(
                        "Stored snapshot exceeds the 512 KB safety limit");
            }
            output.write(buffer, 0, count);
            total += count;
        }
    }
}
