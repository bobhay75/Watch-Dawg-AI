package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;

public final class CanonicalJsonTest {
    @Test
    public void matchesSharedPythonGoldenVector() throws Exception {
        Map<String, Object> collector = new LinkedHashMap<>();
        collector.put("platform", "android");
        collector.put("android_api", 36L);

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("unicode", "é");
        input.put("escaped", "line\n\"quoted\"");
        input.put("collector", collector);
        input.put("array", Arrays.asList("x", null, true));

        try (InputStream stream = getClass().getResourceAsStream(
                "/canonical-v1-golden.json")) {
            assertNotNull(stream);
            String expected = new String(
                    stream.readAllBytes(), StandardCharsets.UTF_8).trim();
            assertEquals(expected, CanonicalJson.encode(input));
        }
    }

    @Test
    public void sortsObjectKeysAndPreservesArrayOrder() {
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("z", 3L);
        nested.put("a", true);

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("second", Arrays.asList("x", null, nested));
        input.put("first", "line\n\"quoted\"");

        assertEquals(
                "{\"first\":\"line\\n\\\"quoted\\\"\",\"second\":[\"x\",null,{\"a\":true,\"z\":3}]}",
                CanonicalJson.encode(input));
    }

    @Test
    public void rejectsFloatingPointNumbers() {
        assertThrows(IllegalArgumentException.class, () -> CanonicalJson.encode(1.25d));
    }

    @Test
    public void rejectsUnpairedSurrogates() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CanonicalJson.encode("bad\ud800value"));
    }
}
