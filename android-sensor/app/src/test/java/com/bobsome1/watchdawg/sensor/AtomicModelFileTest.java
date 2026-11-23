package com.bobsome1.watchdawg.sensor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.util.concurrent.CancellationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public final class AtomicModelFileTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final LocalModelOwner.Check ACTIVE = () -> {};

    private File installed() throws IOException {
        File target = new File(directory.getRoot(), "model.litertlm");
        Files.write(target.toPath(), "prior model".getBytes(StandardCharsets.UTF_8));
        return target;
    }

    private String read(File file) throws IOException {
        return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
    }

    @Test public void successfulReplacementUsesCompleteSameDirectoryStage() throws Exception {
        File target = installed();
        AtomicModelFile storage = new AtomicModelFile();
        File staged = storage.stage(target, new ByteArrayInputStream("new model".getBytes()), 3, 100, ACTIVE);
        assertEquals(target.getParentFile(), staged.getParentFile());
        assertEquals("prior model", read(target));
        storage.commit(staged, target, ACTIVE);
        assertEquals("new model", read(target));
        assertFalse(staged.exists());
    }

    @Test public void unsupportedAtomicMovePreservesThePriorModel() throws Exception {
        File target = installed();
        AtomicModelFile storage = new AtomicModelFile((source, destination) -> {
            assertEquals("prior model", read(target));
            throw new AtomicMoveNotSupportedException(source.toString(), destination.toString(), "synthetic failure");
        });
        File staged = storage.stage(target, new ByteArrayInputStream("new model".getBytes()), 3, 100, ACTIVE);
        assertThrows(AtomicMoveNotSupportedException.class, () -> storage.commit(staged, target, ACTIVE));
        assertEquals("prior model", read(target));
    }

    @Test public void readFailureRemovesStageAndPreservesPriorModel() throws Exception {
        assertStageFailure(IOException.class, new InputStream() {
            @Override public int read() throws IOException { throw new IOException("provider failed"); }
        }, 1, 100, ACTIVE);
    }

    @Test public void providerCloseFailureAlsoRemovesStage() throws Exception {
        assertStageFailure(IOException.class, new ByteArrayInputStream("new model".getBytes()) {
            @Override public void close() throws IOException { throw new IOException("provider close failed"); }
        }, 1, 100, ACTIVE);
    }

    @Test public void oversizedImportRemovesStageAndPreservesPriorModel() throws Exception {
        assertStageFailure(IOException.class, new ByteArrayInputStream(new byte[101]), 1, 100, ACTIVE);
    }

    @Test public void undersizedImportRemovesStageAndPreservesPriorModel() throws Exception {
        assertStageFailure(IOException.class, new ByteArrayInputStream(new byte[2]), 3, 100, ACTIVE);
    }

    @Test public void cancelledImportRemovesStageAndPreservesPriorModel() throws Exception {
        assertStageFailure(CancellationException.class, new ByteArrayInputStream(new byte[10]), 1, 100,
                () -> { throw new CancellationException(); });
    }

    private void assertStageFailure(Class<? extends Throwable> failure, InputStream input,
            long min, long max, LocalModelOwner.Check check) throws Exception {
        File target = installed();
        assertThrows(failure, () -> new AtomicModelFile().stage(target, input, min, max, check));
        assertEquals("prior model", read(target));
        assertArrayEquals(new String[] {"model.litertlm"}, directory.getRoot().list());
    }

    @Test public void cancelledCommitKeepsPriorModel() throws Exception {
        File target = installed();
        AtomicModelFile storage = new AtomicModelFile();
        File staged = storage.stage(target, new ByteArrayInputStream(new byte[10]), 1, 100, ACTIVE);
        assertThrows(CancellationException.class, () -> storage.commit(staged, target,
                () -> { throw new CancellationException(); }));
        assertEquals("prior model", read(target));
    }

    @Test public void rejectsReplacementFromAnotherDirectory() throws Exception {
        File target = installed();
        File other = directory.newFolder("other");
        File staged = new File(other, "staged");
        Files.write(staged.toPath(), new byte[10]);
        assertThrows(IOException.class, () -> new AtomicModelFile().commit(staged, target, ACTIVE));
        assertEquals("prior model", read(target));
    }
}
