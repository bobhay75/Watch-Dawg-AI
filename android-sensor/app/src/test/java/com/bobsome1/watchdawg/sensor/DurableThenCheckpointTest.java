package com.bobsome1.watchdawg.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public final class DurableThenCheckpointTest {
    @Test
    public void commitsCheckpointOnlyAfterDurableWrite() throws Exception {
        List<String> calls = new ArrayList<>();

        DurableThenCheckpoint.run(
                () -> calls.add("durable_write"),
                () -> calls.add("checkpoint_commit"));

        assertEquals(Arrays.asList("durable_write", "checkpoint_commit"), calls);
    }

    @Test
    public void writeFailureDoesNotAdvanceCheckpoint() {
        List<String> calls = new ArrayList<>();

        assertThrows(
                Exception.class,
                () -> DurableThenCheckpoint.run(
                        () -> {
                            calls.add("durable_write");
                            throw new Exception("disk failure");
                        },
                        () -> calls.add("checkpoint_commit")));

        assertEquals(Arrays.asList("durable_write"), calls);
    }

    @Test
    public void checkpointFailureLeavesDurableWriteCompleted() {
        List<String> calls = new ArrayList<>();

        assertThrows(
                Exception.class,
                () -> DurableThenCheckpoint.run(
                        () -> calls.add("durable_write"),
                        () -> {
                            calls.add("checkpoint_commit");
                            throw new Exception("preferences failure");
                        }));

        assertEquals(Arrays.asList("durable_write", "checkpoint_commit"), calls);
    }
}
