package com.bobsome1.watchdawg.sensor;

/** One UI-thread request and its listener/timeout cleanup, including stale callback rejection. */
final class SingleRequest<T> {
    private T current;
    private Runnable cleanup;

    void replace(T request, Runnable cancel) {
        clear();
        current = request;
        cleanup = cancel;
    }

    boolean isCurrent(T request) { return current == request; }

    void clear() {
        Runnable oldCleanup = cleanup;
        current = null;
        cleanup = null;
        if (oldCleanup != null) oldCleanup.run();
    }
}
