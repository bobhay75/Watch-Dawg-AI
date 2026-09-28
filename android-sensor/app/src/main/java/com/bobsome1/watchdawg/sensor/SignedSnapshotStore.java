package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.content.SharedPreferences;
import java.nio.charset.StandardCharsets;

/** Creates signed envelopes and durably queues them until a bound receipt is verified. */
public final class SignedSnapshotStore {
    private static final String PREFERENCES = "watchdawg_sequence";
    private static final String SEQUENCE = "sequence";
    static final int MAX_STORED_BYTES = 512_000;

    private SignedSnapshotStore() {}

    public static synchronized String collectAndSave(Context context) throws Exception {
        return collectAndSave(context, null);
    }

    static synchronized boolean collectAndSavePeriodic(
            Context context, PeriodicCollectionGate.Permit publicationPermit) throws Exception {
        if (publicationPermit == null) {
            throw new NullPointerException("publicationPermit");
        }
        return collectAndSave(context, publicationPermit) != null;
    }

    private static String collectAndSave(
            Context context, PeriodicCollectionGate.Permit publicationPermit) throws Exception {
        SnapshotOutbox outbox = preparedOutbox(context);
        outbox.requireCapacity();
        SequenceUpdate sequence = prepareSequence(context, outbox);
        SnapshotCollector.CollectionResult collection = SnapshotCollector.collect(
                context, sequence.value());
        String canonicalPayload = CanonicalJson.encode(collection.payload());
        String envelope = CanonicalJson.encode(DeviceIdentity.envelope(canonicalPayload));
        byte[] encoded = envelope.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > MAX_STORED_BYTES) {
            throw new IllegalStateException("Signed snapshot exceeds the 512 KB safety limit");
        }
        SnapshotEnvelope verifiedEnvelope = SnapshotEnvelope.verify(encoded);
        if (verifiedEnvelope.sequence != sequence.value()) {
            throw new IllegalStateException("Signed snapshot sequence changed before enqueue");
        }
        DurableThenCheckpoint.CheckedAction publication = () -> DurableThenCheckpoint.run(
                () -> outbox.enqueue(verifiedEnvelope),
                () -> {
                    // Reserve the now-durable sequence first. If the evidence checkpoint
                    // then fails, a retry queues a higher sequence and safely repeats it.
                    sequence.commit();
                    collection.commitState();
                });
        if (publicationPermit == null) {
            // Manual owner-requested scans are intentionally independent of periodic consent.
            publication.run();
        } else if (!CollectionScheduler.publishIfStillEnabled(
                publicationPermit, publication)) {
            return null;
        }
        return envelope;
    }

    public static synchronized String readLatest(Context context) throws Exception {
        SnapshotEnvelope latest = preparedOutbox(context).latest();
        return latest == null ? "" : latest.text;
    }

    public static synchronized int pendingCount(Context context) throws Exception {
        return preparedOutbox(context).pendingCount();
    }

    static synchronized PendingSnapshot readOldestPending(Context context) throws Exception {
        SnapshotOutbox.Pending pending = preparedOutbox(context).oldest();
        return pending == null ? null : new PendingSnapshot(pending);
    }

    static synchronized void acknowledgePending(
            Context context, PendingSnapshot expected) throws Exception {
        if (expected == null) {
            throw new NullPointerException("expected");
        }
        preparedOutbox(context).acknowledge(expected.pending);
    }

    private static SnapshotOutbox preparedOutbox(Context context) throws Exception {
        SnapshotOutbox outbox = new SnapshotOutbox(context);
        outbox.migrateLegacy();
        return outbox;
    }

    private static SequenceUpdate prepareSequence(
            Context context, SnapshotOutbox outbox) throws Exception {
        SharedPreferences preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
        long stored = preferences.getLong(SEQUENCE, 0L);
        long next = OutboxPolicy.nextSequence(
                stored, outbox.highestVerifiedSequence());
        return new SequenceUpdate(
                preferences,
                preferences.contains(SEQUENCE),
                stored,
                next);
    }

    static final class PendingSnapshot {
        private final SnapshotOutbox.Pending pending;

        private PendingSnapshot(SnapshotOutbox.Pending pending) {
            this.pending = pending;
        }

        String envelope() {
            return pending.envelope;
        }

        long sequence() {
            return pending.sequence;
        }

        String payloadSha256() {
            return pending.payloadSha256;
        }
    }

    private static final class SequenceUpdate {
        private final SharedPreferences preferences;
        private final boolean hadPriorValue;
        private final long priorValue;
        private final long value;

        private SequenceUpdate(
                SharedPreferences preferences,
                boolean hadPriorValue,
                long priorValue,
                long value) {
            this.preferences = preferences;
            this.hadPriorValue = hadPriorValue;
            this.priorValue = priorValue;
            this.value = value;
        }

        private long value() {
            return value;
        }

        private void commit() {
            if (preferences.edit().putLong(SEQUENCE, value).commit()) {
                return;
            }
            SharedPreferences.Editor rollback = preferences.edit();
            if (hadPriorValue) {
                rollback.putLong(SEQUENCE, priorValue);
            } else {
                rollback.remove(SEQUENCE);
            }
            // Restore the in-process view even when storage is unavailable.
            rollback.commit();
            throw new IllegalStateException(
                    "Signed snapshot was saved, but its sequence checkpoint could not be persisted; retry may duplicate evidence");
        }
    }
}
