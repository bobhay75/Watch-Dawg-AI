package com.bobsome1.watchdawg.sensor;

import android.content.Context;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;

/** Bounded, ordered, durable queue of signed envelopes awaiting a bound receipt. */
final class SnapshotOutbox {
    private static final String DIRECTORY = "watchdawg_snapshot_outbox_v1";
    private static final String LAST_ACKNOWLEDGED = "last-signed-snapshot-v1.json";
    private static final String LEGACY_LATEST = "latest-signed-snapshot.json";

    private final File directory;
    private final File cache;
    private final File legacy;

    SnapshotOutbox(Context context) {
        directory = context.getDir(DIRECTORY, Context.MODE_PRIVATE);
        cache = new File(context.getFilesDir(), LAST_ACKNOWLEDGED);
        legacy = new File(context.getFilesDir(), LEGACY_LATEST);
        if (!directory.isDirectory()) {
            throw new IllegalStateException("Snapshot outbox directory is unavailable");
        }
    }

    void migrateLegacy() throws Exception {
        byte[] legacyBytes = readLegacyAtomic();
        if (legacyBytes == null) {
            return;
        }
        SnapshotEnvelope record = SnapshotEnvelope.verify(legacyBytes);
        enqueue(record);
        updateCache(record);

        AtomicFile atomicFile = new AtomicFile(legacy);
        atomicFile.delete();
        DurableFile.delete(legacy);
        if (new File(legacy.getAbsolutePath() + ".bak").exists()
                || new File(legacy.getAbsolutePath() + ".new").exists()) {
            throw new IllegalStateException("Legacy snapshot cleanup was incomplete");
        }
    }

    int pendingCount() throws Exception {
        return index().size();
    }

    void requireCapacity() throws Exception {
        if (OutboxPolicy.isFull(pendingCount())) {
            throw new IllegalStateException(
                    "Signed snapshot outbox is full; sync pending evidence before collecting again");
        }
    }

    void enqueue(SnapshotEnvelope record) throws Exception {
        List<OutboxFileName.Entry> entries = index();
        for (OutboxFileName.Entry entry : entries) {
            if (entry.sequence != record.sequence) {
                continue;
            }
            if (!entry.payloadSha256.equals(record.payloadSha256)) {
                throw new IllegalStateException(
                        "Conflicting snapshots share one outbox sequence");
            }
            SnapshotEnvelope existing = readEntry(entry);
            if (!OutboxPolicy.ackMatches(
                    record.sequence,
                    record.payloadSha256,
                    existing.sequence,
                    existing.payloadSha256)) {
                throw new IllegalStateException("Existing outbox entry identity is invalid");
            }
            return;
        }
        if (OutboxPolicy.isFull(entries.size())) {
            throw new IllegalStateException(
                    "Signed snapshot outbox is full; sync pending evidence before collecting again");
        }
        File target = entryFile(record.sequence, record.payloadSha256);
        DurableFile.replace(target, record.encoded);
        SnapshotEnvelope published = readEntry(
                OutboxFileName.parse(target.getName()));
        if (!OutboxPolicy.ackMatches(
                record.sequence,
                record.payloadSha256,
                published.sequence,
                published.payloadSha256)) {
            throw new IllegalStateException("Published outbox entry failed verification");
        }
    }

    Pending oldest() throws Exception {
        List<OutboxFileName.Entry> entries = index();
        return entries.isEmpty() ? null : new Pending(readEntry(entries.get(0)));
    }

    SnapshotEnvelope latest() throws Exception {
        List<OutboxFileName.Entry> entries = index();
        SnapshotEnvelope pending = entries.isEmpty()
                ? null : readEntry(entries.get(entries.size() - 1));
        SnapshotEnvelope acknowledged = readCache();
        if (pending == null) {
            return acknowledged;
        }
        if (acknowledged != null
                && pending.sequence == acknowledged.sequence
                && !pending.payloadSha256.equals(acknowledged.payloadSha256)) {
            throw new IllegalStateException(
                    "Pending snapshot conflicts with last acknowledged sequence");
        }
        if (acknowledged == null || pending.sequence >= acknowledged.sequence) {
            return pending;
        }
        return acknowledged;
    }

    long highestVerifiedSequence() throws Exception {
        long highest = 0L;
        for (OutboxFileName.Entry entry : index()) {
            SnapshotEnvelope record = readEntry(entry);
            highest = Math.max(highest, record.sequence);
        }
        SnapshotEnvelope acknowledged = readCache();
        return acknowledged == null ? highest : Math.max(highest, acknowledged.sequence);
    }

    void acknowledge(Pending expected) throws Exception {
        List<OutboxFileName.Entry> entries = index();
        OutboxFileName.Entry match = null;
        for (OutboxFileName.Entry entry : entries) {
            if (entry.sequence == expected.sequence) {
                match = entry;
                break;
            }
        }
        if (match == null) {
            SnapshotEnvelope acknowledged = readCache();
            if (acknowledged != null && OutboxPolicy.ackMatches(
                    expected.sequence,
                    expected.payloadSha256,
                    acknowledged.sequence,
                    acknowledged.payloadSha256)) {
                return;
            }
            throw new IllegalStateException("Pending snapshot disappeared before acknowledgement");
        }
        if (entries.get(0).sequence != expected.sequence
                || !match.payloadSha256.equals(expected.payloadSha256)) {
            throw new IllegalStateException(
                    "Acknowledgement does not identify the oldest pending snapshot");
        }

        // Re-open and reverify under the store lock immediately before deletion.
        SnapshotEnvelope actual = readEntry(match);
        if (!OutboxPolicy.ackMatches(
                expected.sequence,
                expected.payloadSha256,
                actual.sequence,
                actual.payloadSha256)) {
            throw new IllegalStateException("Pending snapshot changed before acknowledgement");
        }
        updateCache(actual);
        DurableFile.delete(entryFile(actual.sequence, actual.payloadSha256));
    }

    private void updateCache(SnapshotEnvelope candidate) throws Exception {
        SnapshotEnvelope existing = readCache();
        if (existing != null) {
            if (existing.sequence > candidate.sequence) {
                return;
            }
            if (existing.sequence == candidate.sequence) {
                if (!existing.payloadSha256.equals(candidate.payloadSha256)) {
                    throw new IllegalStateException(
                            "Last-snapshot cache conflicts with acknowledged sequence");
                }
                return;
            }
        }
        DurableFile.replace(cache, candidate.encoded);
        SnapshotEnvelope persisted = readCache();
        if (persisted == null || !OutboxPolicy.ackMatches(
                candidate.sequence,
                candidate.payloadSha256,
                persisted.sequence,
                persisted.payloadSha256)) {
            throw new IllegalStateException("Last-snapshot cache failed verification");
        }
    }

    private SnapshotEnvelope readCache() throws Exception {
        DurableFile.deleteTemporary(new File(cache.getAbsolutePath() + ".tmp"));
        byte[] encoded = DurableFile.read(
                cache, SignedSnapshotStore.MAX_STORED_BYTES);
        return encoded == null ? null : SnapshotEnvelope.verify(encoded);
    }

    private SnapshotEnvelope readEntry(OutboxFileName.Entry entry) throws Exception {
        if (entry == null) {
            throw new IllegalStateException("Outbox filename is invalid");
        }
        byte[] encoded = DurableFile.read(
                new File(directory, entry.fileName),
                SignedSnapshotStore.MAX_STORED_BYTES);
        if (encoded == null) {
            throw new IllegalStateException("Indexed outbox entry is missing");
        }
        SnapshotEnvelope record = SnapshotEnvelope.verify(encoded);
        if (!OutboxPolicy.ackMatches(
                entry.sequence,
                entry.payloadSha256,
                record.sequence,
                record.payloadSha256)) {
            throw new IllegalStateException("Outbox filename does not match signed payload");
        }
        return record;
    }

    private List<OutboxFileName.Entry> index() throws Exception {
        File[] files = directory.listFiles();
        if (files == null) {
            throw new IllegalStateException("Could not enumerate signed snapshot outbox");
        }
        List<String> committedNames = new ArrayList<>();
        for (File file : files) {
            String name = file.getName();
            if (name.endsWith(".tmp")) {
                String baseName = name.substring(0, name.length() - 4);
                if (OutboxFileName.parse(baseName) == null) {
                    throw new IllegalStateException("Malformed file in signed snapshot outbox");
                }
                DurableFile.deleteTemporary(file);
                continue;
            }
            if (!file.isFile()) {
                throw new IllegalStateException("Unexpected path in signed snapshot outbox");
            }
            committedNames.add(name);
        }
        try {
            return OutboxFileName.ordered(committedNames);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("Signed snapshot outbox index is invalid", invalid);
        }
    }

    private File entryFile(long sequence, String payloadSha256) {
        return new File(directory, OutboxFileName.format(sequence, payloadSha256));
    }

    private byte[] readLegacyAtomic() throws Exception {
        AtomicFile atomicFile = new AtomicFile(legacy);
        FileInputStream recovered;
        try {
            recovered = atomicFile.openRead();
        } catch (FileNotFoundException missing) {
            return null;
        }
        try (FileInputStream input = recovered) {
            return BoundedInput.read(input, SignedSnapshotStore.MAX_STORED_BYTES);
        }
    }

    static final class Pending {
        final String envelope;
        final long sequence;
        final String payloadSha256;

        private Pending(SnapshotEnvelope record) {
            envelope = record.text;
            sequence = record.sequence;
            payloadSha256 = record.payloadSha256;
        }
    }
}
