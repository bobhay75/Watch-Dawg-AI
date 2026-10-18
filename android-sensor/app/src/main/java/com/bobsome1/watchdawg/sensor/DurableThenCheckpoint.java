package com.bobsome1.watchdawg.sensor;

/**
 * Encodes the evidence durability invariant: never advance a source checkpoint until the
 * corresponding signed artifact has been durably published.
 */
final class DurableThenCheckpoint {
    private DurableThenCheckpoint() {}

    static void run(CheckedAction durableWrite, CheckedAction checkpointCommit) throws Exception {
        durableWrite.run();
        checkpointCommit.run();
    }

    @FunctionalInterface
    interface CheckedAction {
        void run() throws Exception;
    }
}
