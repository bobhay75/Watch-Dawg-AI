package com.bobsome1.watchdawg.sensor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;
import static org.junit.Assert.*;

public final class LocalModelOwnerTest {
    private static final LocalModelOwner.Check ACTIVE = () -> {};

    private static final class Resource {
        final String name;
        final List<String> closed;
        Resource(String name, List<String> closed) { this.name = name; this.closed = closed; }
        void close() { closed.add(name); }
    }

    private LocalModelOwner<Resource, Resource> owner() {
        return new LocalModelOwner<>(Resource::close, Resource::close);
    }

    @Test public void failedInitializationClosesUnpublishedEngine() throws Exception {
        List<String> closed = new ArrayList<>();
        LocalModelOwner<Resource, Resource> owner = owner();
        IOException original = new IOException("initialize failed");
        assertSame(original, assertThrows(IOException.class, () -> owner.load(
                () -> new Resource("engine", closed), e -> { throw original; },
                e -> { throw new AssertionError("Must not create a conversation"); }, ACTIVE)));
        assertEquals(Arrays.asList("engine"), closed);
        assertFalse(owner.isReady());
        owner.close();
        assertEquals(1, closed.size());
    }

    @Test public void failedConversationCreationClosesInitializedEngine() {
        List<String> closed = new ArrayList<>();
        LocalModelOwner<Resource, Resource> owner = owner();
        assertThrows(IOException.class, () -> owner.load(() -> new Resource("engine", closed),
                e -> {}, e -> { throw new IOException("conversation failed"); }, ACTIVE));
        assertEquals(Arrays.asList("engine"), closed);
        assertFalse(owner.isReady());
    }

    @Test public void cancellationBeforePublicationClosesBothInOrder() {
        List<String> closed = new ArrayList<>();
        AtomicBoolean cancelled = new AtomicBoolean();
        LocalModelOwner<Resource, Resource> owner = owner();
        assertThrows(CancellationException.class, () -> owner.load(
                () -> new Resource("engine", closed), e -> {}, e -> {
                    cancelled.set(true);
                    return new Resource("conversation", closed);
                }, () -> { if (cancelled.get()) throw new CancellationException(); }));
        assertEquals(Arrays.asList("conversation", "engine"), closed);
        assertFalse(owner.isReady());
    }

    @Test public void shutdownDuringBlockingInitializeCannotPublishResources() throws Exception {
        List<String> closed = new ArrayList<>();
        LocalModelOwner<Resource, Resource> owner = owner();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<?> loading = worker.submit(() -> {
                assertThrows(IllegalStateException.class, () -> owner.load(
                        () -> new Resource("engine", closed), e -> {
                            entered.countDown();
                            assertTrue(release.await(3, TimeUnit.SECONDS));
                        }, e -> { throw new AssertionError("Shutdown must prevent creation"); }, ACTIVE));
            });
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            owner.requestShutdown();
            release.countDown();
            loading.get(3, TimeUnit.SECONDS);
            assertFalse(owner.isReady());
            assertEquals(Arrays.asList("engine"), closed);
        } finally {
            release.countDown();
            worker.shutdownNow();
        }
    }

    @Test public void destroyCannotCloseConversationWhileNativeCallIsRunning() throws Exception {
        verifyExclusiveCleanup(true);
    }

    @Test public void removeCannotCloseOrDeleteModelWhileNativeCallIsRunning() throws Exception {
        verifyExclusiveCleanup(false);
    }

    private void verifyExclusiveCleanup(boolean shutdown) throws Exception {
        List<String> closed = new ArrayList<>();
        LocalModelOwner<Resource, Resource> owner = owner();
        owner.load(() -> new Resource("engine", closed), e -> {},
                e -> new Resource("conversation", closed), ACTIVE);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch cleanupStarted = new CountDownLatch(1);
        AtomicBoolean nativeFinished = new AtomicBoolean();
        AtomicBoolean fileRemoved = new AtomicBoolean();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<?> inference = workers.submit(() -> {
                try {
                    owner.use(c -> {
                        entered.countDown();
                        assertTrue(release.await(3, TimeUnit.SECONDS));
                        assertTrue("Native resources were closed during inference", closed.isEmpty());
                        nativeFinished.set(true);
                        return null;
                    }, ACTIVE);
                } catch (IllegalStateException error) {
                    if (!shutdown) throw error;
                } catch (Exception error) {
                    throw new AssertionError(error);
                }
            });
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            if (shutdown) owner.requestShutdown();
            Future<?> cleanup = workers.submit(() -> {
                cleanupStarted.countDown();
                try {
                    if (shutdown) owner.close();
                    else owner.reset(() -> {
                        assertTrue(nativeFinished.get());
                        assertEquals(Arrays.asList("conversation", "engine"), closed);
                        fileRemoved.set(true);
                    }, ACTIVE);
                } catch (Exception error) {
                    throw new AssertionError(error);
                }
            });
            assertTrue(cleanupStarted.await(3, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> cleanup.get(100, TimeUnit.MILLISECONDS));
            assertFalse(fileRemoved.get());
            release.countDown();
            inference.get(3, TimeUnit.SECONDS);
            cleanup.get(3, TimeUnit.SECONDS);
            assertEquals(Arrays.asList("conversation", "engine"), closed);
            assertEquals(!shutdown, fileRemoved.get());
            assertFalse(owner.isReady());
        } finally {
            release.countDown();
            workers.shutdownNow();
        }
    }

    @Test public void conversationCloseFailureStillClosesEngineExactlyOnce() throws Exception {
        List<String> closed = new ArrayList<>();
        LocalModelOwner<Resource, Resource> owner = new LocalModelOwner<>(Resource::close, c -> {
            c.close();
            throw new IOException("conversation close failed");
        });
        owner.load(() -> new Resource("engine", closed), e -> {},
                e -> new Resource("conversation", closed), ACTIVE);
        assertThrows(IOException.class, owner::close);
        owner.close();
        assertEquals(Arrays.asList("conversation", "engine"), closed);
        assertFalse(owner.isReady());
    }

    @Test public void shutdownRejectsNewWork() {
        LocalModelOwner<Resource, Resource> owner = owner();
        owner.requestShutdown();
        assertThrows(IllegalStateException.class, () -> owner.load(
                () -> { throw new AssertionError("Must not allocate after shutdown"); },
                e -> {}, e -> null, ACTIVE));
    }
}
