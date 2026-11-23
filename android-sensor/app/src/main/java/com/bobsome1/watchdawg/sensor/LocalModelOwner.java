package com.bobsome1.watchdawg.sensor;

import java.util.concurrent.atomic.AtomicBoolean;

/** Serial ownership of a native engine and conversation; callers use a worker thread. */
final class LocalModelOwner<E, C> {
    interface Factory<T> { T create() throws Exception; }
    interface Action<T> { void run(T value) throws Exception; }
    interface Operation<T, R> { R run(T value) throws Exception; }
    interface Check { void run(); }
    interface AfterClose { void run() throws Exception; }

    private final Action<E> closeEngine;
    private final Action<C> closeConversation;
    private final AtomicBoolean shutdownRequested = new AtomicBoolean();
    private E engine;
    private C conversation;
    private volatile boolean ready;

    LocalModelOwner(Action<E> closeEngine, Action<C> closeConversation) {
        this.closeEngine = closeEngine;
        this.closeConversation = closeConversation;
    }

    boolean isReady() { return ready; }

    /** Does not wait for native work and is safe to call from Activity.onDestroy. */
    void requestShutdown() { shutdownRequested.set(true); }

    synchronized void load(Factory<E> factory, Action<E> initialize,
            Operation<E, C> createConversation, Check cancellation) throws Exception {
        requireOpen(cancellation);
        release();
        E pendingEngine = null;
        C pendingConversation = null;
        Throwable failure = null;
        try {
            pendingEngine = factory.create();
            initialize.run(pendingEngine);
            requireOpen(cancellation);
            pendingConversation = createConversation.run(pendingEngine);
            requireOpen(cancellation);
            engine = pendingEngine;
            conversation = pendingConversation;
            pendingEngine = null;
            pendingConversation = null;
            ready = true;
        } catch (Exception | Error error) {
            failure = error;
            throw error;
        } finally {
            try {
                closeBoth(pendingConversation, pendingEngine);
            } catch (Exception cleanup) {
                if (failure != null) failure.addSuppressed(cleanup);
                else throw cleanup;
            }
        }
    }

    /** The operation must return only after native work has actually finished. */
    synchronized <R> R use(Operation<C, R> operation, Check cancellation) throws Exception {
        requireOpen(cancellation);
        if (conversation == null) throw new IllegalStateException("Load the local model first.");
        R result = operation.run(conversation);
        requireOpen(cancellation);
        return result;
    }

    /** Close and file replacement/removal share the same lock as load/inference. */
    synchronized void reset(AfterClose afterClose, Check cancellation) throws Exception {
        requireOpen(cancellation);
        release();
        requireOpen(cancellation);
        afterClose.run();
    }

    /** Waits for any blocking native call before closing; never run on the UI thread. */
    synchronized void close() throws Exception {
        shutdownRequested.set(true);
        release();
    }

    private void requireOpen(Check cancellation) {
        cancellation.run();
        if (shutdownRequested.get()) throw new IllegalStateException("Local AI has closed.");
    }

    private void release() throws Exception {
        C oldConversation = conversation;
        E oldEngine = engine;
        conversation = null;
        engine = null;
        ready = false;
        closeBoth(oldConversation, oldEngine);
    }

    private void closeBoth(C oldConversation, E oldEngine) throws Exception {
        Exception failure = null;
        try {
            if (oldConversation != null) closeConversation.run(oldConversation);
        } catch (Exception error) {
            failure = error;
        } finally {
            try {
                if (oldEngine != null) closeEngine.run(oldEngine);
            } catch (Exception error) {
                if (failure == null) failure = error;
                else failure.addSuppressed(error);
            }
        }
        if (failure != null) throw failure;
    }
}
