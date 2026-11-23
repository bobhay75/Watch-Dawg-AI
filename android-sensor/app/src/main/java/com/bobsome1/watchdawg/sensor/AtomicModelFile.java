package com.bobsome1.watchdawg.sensor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Stage beside the installed model, then replace it in one atomic filesystem operation. */
final class AtomicModelFile {
    interface Mover { void move(Path source, Path target) throws IOException; }
    private final Mover mover;

    AtomicModelFile() {
        this((source, target) -> Files.move(source, target,
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING));
    }

    AtomicModelFile(Mover mover) { this.mover = mover; }

    File stage(File target, InputStream input, long minBytes, long maxBytes,
            LocalModelOwner.Check cancellation) throws IOException {
        if (minBytes < 0 || maxBytes < minBytes) throw new IllegalArgumentException("Invalid model bounds");
        File staged = null;
        // Own the source too: a provider's close failure must also discard the staged copy.
        try (InputStream source = input) {
            staged = File.createTempFile(target.getName() + ".", ".tmp", target.getParentFile());
            try (FileOutputStream output = new FileOutputStream(staged)) {
                byte[] buffer = new byte[8192];
                long bytes = 0;
                while (true) {
                    cancellation.run();
                    int count = source.read(buffer);
                    if (count < 0) break;
                    if (count > maxBytes - bytes) throw new IOException("Model file is over the import limit.");
                    output.write(buffer, 0, count);
                    bytes += count;
                }
                cancellation.run();
                if (bytes < minBytes) throw new IOException("Selected file is too small to be a supported model.");
                output.getFD().sync();
            }
        } catch (IOException | RuntimeException | Error failure) {
            try {
                if (staged != null) Files.deleteIfExists(staged.toPath());
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
        return staged;
    }

    void commit(File staged, File target, LocalModelOwner.Check cancellation) throws IOException {
        if (!staged.getCanonicalFile().getParentFile().equals(target.getCanonicalFile().getParentFile())) {
            throw new IOException("Model replacement must stay in the same directory.");
        }
        cancellation.run();
        // No delete-first operation or non-atomic fallback: a rejected move keeps the prior model.
        mover.move(staged.toPath(), target.toPath());
    }
}
