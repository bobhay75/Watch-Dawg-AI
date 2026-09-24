package com.bobsome1.watchdawg.sensor;

import android.app.job.JobParameters;
import android.app.job.JobService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class CollectionJobService extends JobService {
    private final Object runLock = new Object();
    private final JobRunGate runGate = new JobRunGate();
    private ActiveRun activeRun;

    @Override
    public boolean onStartJob(JobParameters parameters) {
        PeriodicCollectionGate.Permit publicationPermit =
                CollectionScheduler.beginPeriodicRun(getApplicationContext());
        if (publicationPermit == null) {
            // A stale callback can arrive after cancellation. Do not start collection without
            // persisted owner consent.
            return false;
        }
        final ActiveRun run;
        synchronized (runLock) {
            // JobScheduler does not normally overlap one JobInfo, but refusing an
            // unexpected second callback is safer than losing ownership of the first.
            if (activeRun != null) {
                return false;
            }
            run = new ActiveRun(
                    runGate.open(),
                    publicationPermit,
                    parameters,
                    Executors.newSingleThreadExecutor());
            activeRun = run;
            try {
                // Publish the Future while holding the ownership lock. A stop callback
                // can therefore never observe this run before its cancellable task.
                run.pending = run.executor.submit(() -> {
                    try {
                        SignedSnapshotStore.collectAndSavePeriodic(
                                getApplicationContext(), run.publicationPermit);
                    } catch (Exception ignored) {
                        // A later job retries. No sensitive device data or credentials
                        // are logged.
                    }
                    try {
                        // Phone Guard is a separate local owner-baseline check. Run it even if
                        // signed collection failed so security monitoring is not coupled to sync.
                        PhoneGuard.scanAndNotify(getApplicationContext());
                    } catch (RuntimeException ignored) {
                        // A later periodic run retries; do not log package names.
                    } finally {
                        finishIfActive(run);
                    }
                });
            } catch (RuntimeException submissionFailure) {
                runGate.stop(run.token);
                activeRun = null;
                CollectionScheduler.cancelPeriodicRun(run.publicationPermit);
                run.executor.shutdownNow();
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters parameters) {
        ActiveRun stopped;
        synchronized (runLock) {
            stopped = activeRun;
            // JobParameters delivered to onStopJob is only guaranteed to describe
            // the same job; Binder need not preserve Java object identity.
            if (stopped == null
                    || stopped.parameters.getJobId() != parameters.getJobId()) {
                return false;
            }
            if (!runGate.stop(stopped.token)) {
                return false;
            }
            // Close durable publication before relinquishing run ownership. Otherwise the worker
            // could enter the publication gate between this synchronized block and interruption.
            stopped.invalidatePublication();
            activeRun = null;
        }
        stopped.interrupt();
        return true;
    }

    @Override
    public void onDestroy() {
        ActiveRun stopped;
        synchronized (runLock) {
            stopped = activeRun;
            if (stopped != null && runGate.stop(stopped.token)) {
                stopped.invalidatePublication();
                activeRun = null;
            } else {
                stopped = null;
            }
        }
        if (stopped != null) {
            stopped.interrupt();
        }
        super.onDestroy();
    }

    private void finishIfActive(ActiveRun run) {
        try {
            synchronized (runLock) {
                if (activeRun != run || !runGate.complete(run.token)) {
                    return;
                }
                activeRun = null;
                // Keep completion ordered with the stop gate. If onStopJob won the
                // lock, completion is suppressed; if this won, the framework sees
                // jobFinished before any later stale stop callback can acquire it.
                jobFinished(run.parameters, false);
            }
        } finally {
            run.executor.shutdown();
        }
    }

    private static final class ActiveRun {
        private final long token;
        private final PeriodicCollectionGate.Permit publicationPermit;
        private final JobParameters parameters;
        private final ExecutorService executor;
        private volatile Future<?> pending;

        private ActiveRun(
                long token,
                PeriodicCollectionGate.Permit publicationPermit,
                JobParameters parameters,
                ExecutorService executor) {
            this.token = token;
            this.publicationPermit = publicationPermit;
            this.parameters = parameters;
            this.executor = executor;
        }

        private void invalidatePublication() {
            CollectionScheduler.cancelPeriodicRun(publicationPermit);
        }

        private void interrupt() {
            Future<?> task = pending;
            if (task != null) {
                task.cancel(true);
            }
            executor.shutdownNow();
        }
    }
}
