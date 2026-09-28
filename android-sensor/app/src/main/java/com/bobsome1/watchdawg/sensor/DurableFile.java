package com.bobsome1.watchdawg.sensor;

import android.system.Os;
import android.system.OsConstants;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/** Same-directory fsync + rename publication for API 26 durable files. */
final class DurableFile {
    private DurableFile() {}

    static byte[] read(File target, int maxBytes) throws Exception {
        if (!target.exists()) {
            return null;
        }
        if (!target.isFile()) {
            throw new IllegalStateException("Durable path is not a regular file");
        }
        try (FileInputStream input = new FileInputStream(target)) {
            return BoundedInput.read(input, maxBytes);
        }
    }

    static void replace(File target, byte[] data) throws Exception {
        File parent = requireParentDirectory(target);
        File temporary = new File(parent, target.getName() + ".tmp");
        boolean renamed = false;
        try {
            try (FileOutputStream output = new FileOutputStream(temporary, false)) {
                output.write(data);
                output.flush();
                output.getFD().sync();
            }
            Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath());
            renamed = true;
            syncDirectory(parent);
        } finally {
            if (!renamed && temporary.exists()) {
                // An abandoned temporary file is never a committed queue entry.
                temporary.delete();
            }
        }
    }

    static void delete(File target) throws Exception {
        File parent = requireParentDirectory(target);
        if (target.exists() && !target.delete()) {
            throw new IllegalStateException("Could not delete acknowledged outbox entry");
        }
        syncDirectory(parent);
        if (target.exists()) {
            throw new IllegalStateException("Acknowledged outbox entry still exists");
        }
    }

    static void deleteTemporary(File temporary) throws Exception {
        if (!temporary.exists()) {
            return;
        }
        File parent = requireParentDirectory(temporary);
        if (!temporary.delete()) {
            throw new IllegalStateException("Could not remove abandoned outbox temporary file");
        }
        syncDirectory(parent);
    }

    private static File requireParentDirectory(File target) {
        File parent = target.getParentFile();
        if (parent == null || !parent.isDirectory()) {
            throw new IllegalStateException("Durable parent directory is unavailable");
        }
        return parent;
    }

    private static void syncDirectory(File directory) throws Exception {
        FileDescriptor descriptor = Os.open(
                directory.getAbsolutePath(),
                OsConstants.O_RDONLY,
                0);
        try {
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }
}
