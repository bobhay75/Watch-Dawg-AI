package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class MetadataNormalizerTest {
    @Test
    public void acceptsValidSecurityPatchAndAppVersion() {
        assertEquals("2026-09-05", MetadataNormalizer.securityPatch("2026-09-05"));
        assertEquals("1.2.3-rc_1+7", MetadataNormalizer.appVersion("1.2.3-rc_1+7"));
    }

    @Test
    public void mapsUnavailableOrMalformedSecurityPatchToUnknown() {
        assertEquals("unknown", MetadataNormalizer.securityPatch(null));
        assertEquals("unknown", MetadataNormalizer.securityPatch(""));
        assertEquals("unknown", MetadataNormalizer.securityPatch("2026-02-30"));
        assertEquals("unknown", MetadataNormalizer.securityPatch("not-a-date"));
    }

    @Test
    public void mapsOutOfSchemaAppVersionToUnknown() {
        assertEquals("unknown", MetadataNormalizer.appVersion(null));
        assertEquals("unknown", MetadataNormalizer.appVersion(""));
        assertEquals("unknown", MetadataNormalizer.appVersion(" version 1 "));
        assertEquals("unknown", MetadataNormalizer.appVersion("_starts_wrong"));
        assertEquals("unknown", MetadataNormalizer.appVersion("a".repeat(65)));
    }
}
