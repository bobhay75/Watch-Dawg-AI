package com.bobsome1.watchdawg.sensor;

/** Thread-safe ownership gate for one asynchronous JobService run. */
final class JobRunGate {
    private long nextToken;
    private long activeToken;

    synchronized long open() {
        if (activeToken != 0L) {
            throw new IllegalStateException("A job run is already active");
        }
        if (nextToken == Long.MAX_VALUE) {
            throw new IllegalStateException("Job run token space exhausted");
        }
        activeToken = ++nextToken;
        return activeToken;
    }

    synchronized boolean complete(long token) {
        return consume(token);
    }

    synchronized boolean stop(long token) {
        return consume(token);
    }

    synchronized boolean isActive(long token) {
        return token != 0L && activeToken == token;
    }

    private boolean consume(long token) {
        if (token == 0L || activeToken != token) {
            return false;
        }
        activeToken = 0L;
        return true;
    }
}
