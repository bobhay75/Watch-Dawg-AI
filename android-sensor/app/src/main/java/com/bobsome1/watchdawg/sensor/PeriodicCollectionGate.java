package com.bobsome1.watchdawg.sensor;

/**
 * Linearizes periodic-collection consent with durable snapshot publication.
 *
 * <p>Collection and signing can take place without holding this gate. The final outbox write and
 * its checkpoints run under the gate, so revocation either happens before publication (and rejects
 * it) or after publication has completely finished. Re-enabling rotates the epoch and never makes
 * a permit from an older consent period valid again.
 */
final class PeriodicCollectionGate {
    private enum State {
        UNKNOWN,
        ENABLED,
        DISABLED
    }

    private State state = State.UNKNOWN;
    private Object epoch = new Object();

    synchronized Permit open(boolean persistedEnabled) {
        if (!persistedEnabled) {
            if (state != State.DISABLED) {
                state = State.DISABLED;
                epoch = new Object();
            }
            return null;
        }
        if (state == State.UNKNOWN) {
            state = State.ENABLED;
        }
        return state == State.ENABLED ? new Permit(epoch) : null;
    }

    synchronized void grant() {
        state = State.ENABLED;
        epoch = new Object();
    }

    synchronized void revoke() {
        state = State.DISABLED;
        epoch = new Object();
    }

    synchronized void cancel(Permit permit) {
        if (permit != null) {
            permit.active = false;
        }
    }

    synchronized boolean publish(Permit permit, DurableThenCheckpoint.CheckedAction action)
            throws Exception {
        if (permit == null || !permit.active || state != State.ENABLED || permit.epoch != epoch) {
            return false;
        }
        // A permit authorizes one terminal publication attempt only.
        permit.active = false;
        action.run();
        return true;
    }

    static final class Permit {
        private final Object epoch;
        private boolean active = true;

        private Permit(Object epoch) {
            this.epoch = epoch;
        }
    }
}
