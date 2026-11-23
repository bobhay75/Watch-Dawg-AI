package com.bobsome1.watchdawg.sensor;

/** Selects whether an observed delta may advance its durable baseline. */
final class DeltaCheckpoint {
    private DeltaCheckpoint() {}

    static String select(
            String previous,
            String observed,
            boolean evidenceRequired,
            boolean evidenceEmitted) {
        return evidenceRequired && !evidenceEmitted ? previous : observed;
    }
}
