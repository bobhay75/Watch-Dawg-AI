package com.bobsome1.watchdawg.sensor;

/** Tracks whether editable UI input changed after an asynchronous operation began. */
final class EditGeneration {
    private long generation;

    long markChanged() {
        return ++generation;
    }

    long snapshot() {
        return generation;
    }

    boolean isCurrent(long expectedGeneration) {
        return generation == expectedGeneration;
    }
}
