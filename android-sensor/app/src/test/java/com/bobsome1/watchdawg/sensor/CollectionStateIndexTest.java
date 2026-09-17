package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import org.junit.Test;

public final class CollectionStateIndexTest {
    @Test
    public void indexesInventoryAndPermissionsInOnePass() {
        Map<String, String> inventory = CollectionStateIndex.inventory(
                new HashSet<>(Arrays.asList("pkg-a|1", "pkg-b|2")));
        assertEquals("pkg-a|1", inventory.get("pkg-a"));

        CollectionStateIndex.PermissionIndex permissions =
                CollectionStateIndex.permissions(new HashSet<>(Arrays.asList(
                        "pkg-a|CAMERA|1",
                        "pkg-a|RECORD_AUDIO|0",
                        "pkg-b|CAMERA|0")));
        assertEquals("pkg-a|CAMERA|1", permissions.get("pkg-a", "CAMERA"));
        assertEquals(2, permissions.forPackage("pkg-a").size());
    }

    @Test
    public void rejectsConflictingOrMalformedState() {
        assertThrows(
                IllegalStateException.class,
                () -> CollectionStateIndex.inventory(
                        new HashSet<>(Arrays.asList("pkg-a|1", "pkg-a|2"))));
        assertThrows(
                IllegalStateException.class,
                () -> CollectionStateIndex.permissions(
                        new HashSet<>(Arrays.asList(
                                "pkg-a|CAMERA|1",
                                "pkg-a|CAMERA|0"))));
        assertThrows(
                IllegalStateException.class,
                () -> CollectionStateIndex.inventory(
                        new HashSet<>(Collections.singletonList("malformed"))));
    }
}
